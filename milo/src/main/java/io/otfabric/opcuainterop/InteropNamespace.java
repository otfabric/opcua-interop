package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.sdk.core.AccessLevel;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.UaNodeManager;
import org.eclipse.milo.opcua.sdk.server.ManagedNamespaceWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.items.DataItem;
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.methods.AbstractMethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.methods.MethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.nodes.UaFolderNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.sdk.server.util.SubscriptionModel;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.*;
import org.eclipse.milo.opcua.stack.core.types.structured.Argument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class InteropNamespace extends ManagedNamespaceWithLifecycle {

    private static final Logger LOG = LoggerFactory.getLogger(InteropNamespace.class);

    private final FixtureModel fixture;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2,
            r -> { Thread t = new Thread(r, "interop-behavior"); t.setDaemon(true); return t; });

    private final Map<String, UaNode> nodeByFixtureId = new LinkedHashMap<>();

    private SubscriptionModel subscriptionModel;

    public InteropNamespace(OpcUaServer server, FixtureModel fixture) {
        super(server, fixture.namespaces.get(0).uri);
        this.fixture = fixture;

        getLifecycleManager().addStartupTask(this::buildAddressSpace);
        getLifecycleManager().addStartupTask(this::setupBehaviors);
        getLifecycleManager().addStartupTask(() -> {
            subscriptionModel = new SubscriptionModel(server, this);
            subscriptionModel.startup();
        });
        getLifecycleManager().addShutdownTask(() -> {
            if (subscriptionModel != null) subscriptionModel.shutdown();
        });
        getLifecycleManager().addShutdownTask(scheduler::shutdownNow);
    }

    // -------------------------------------------------------------------------
    // Address space construction
    // -------------------------------------------------------------------------

    private void buildAddressSpace() {
        for (FixtureModel.NodeDef nd : fixture.nodes) {
            try {
                UaNode node = createNode(nd);
                if (node == null) continue;
                getNodeManager().addNode(node);
                nodeByFixtureId.put(nd.nodeId, node);
                connectToParent(node, nd);
            } catch (Exception e) {
                LOG.warn("Failed to create node {}: {}", nd.nodeId, e.getMessage(), e);
            }
        }
    }

    private UaNode createNode(FixtureModel.NodeDef nd) {
        NodeId        nodeId  = resolveNodeId(nd.nodeId);
        QualifiedName bn      = parseBrowseName(nd.browseName);
        LocalizedText dn      = LocalizedText.english(nd.displayName != null ? nd.displayName : "");
        LocalizedText desc    = LocalizedText.english(nd.description != null ? nd.description : "");

        String nodeClass = nd.nodeClass != null ? nd.nodeClass : "Object";
        switch (nodeClass) {
            case "Variable":
                return buildVariableNode(nd, nodeId, bn, dn, desc);
            case "Method":
                return buildMethodNode(nd, nodeId, bn, dn, desc);
            default:
                UaFolderNode folder = new UaFolderNode(getNodeContext(), nodeId, bn, dn);
                folder.setDescription(desc);
                return folder;
        }
    }

    private UaVariableNode buildVariableNode(FixtureModel.NodeDef nd,
                                              NodeId nodeId, QualifiedName bn,
                                              LocalizedText dn, LocalizedText desc) {
        Set<AccessLevel> levels = buildAccessLevels(nd.accessLevel);
        if (levels.isEmpty()) levels = EnumSet.of(AccessLevel.CurrentRead);

        NodeId typeDefId  = nd.typeDefinition != null
                ? resolveNodeId(nd.typeDefinition) : Identifiers.BaseDataVariableType;
        NodeId dataTypeId = getDataTypeId(nd.dataType);

        UaVariableNode node = UaVariableNode.builder(getNodeContext())
                .setNodeId(nodeId)
                .setBrowseName(bn)
                .setDisplayName(dn)
                .setDescription(desc)
                .setDataType(dataTypeId)
                .setTypeDefinition(typeDefId)
                .setValueRank(nd.valueRank)
                .setAccessLevel(levels)
                .setUserAccessLevel(levels)
                .build();

        if (nd.value != null) {
            Variant variant = buildVariant(nd.value, nd.dataType, nd.valueRank);
            node.setValue(new DataValue(variant));
        }
        return node;
    }

    private UaMethodNode buildMethodNode(FixtureModel.NodeDef nd,
                                          NodeId nodeId, QualifiedName bn,
                                          LocalizedText dn, LocalizedText desc) {
        UaMethodNode node = UaMethodNode.builder(getNodeContext())
                .setNodeId(nodeId)
                .setBrowseName(bn)
                .setDisplayName(dn)
                .setDescription(desc)
                .setExecutable(true)
                .setUserExecutable(true)
                .build();

        Argument[] inArgs  = buildArguments(nd.inputArguments);
        Argument[] outArgs = buildArguments(nd.outputArguments);
        node.setInvocationHandler(createMethodHandler(nd.methodBehavior, node, inArgs, outArgs));
        addMethodArgumentProperties(node, inArgs, outArgs);
        return node;
    }

    private void addMethodArgumentProperties(UaMethodNode methodNode,
                                              Argument[] inputArgs, Argument[] outputArgs) {
        String id = methodNode.getNodeId().getIdentifier().toString();
        Set<AccessLevel> ro = EnumSet.of(AccessLevel.CurrentRead);

        if (inputArgs.length > 0) {
            NodeId propId = new NodeId(getNamespaceIndex(), id + ".InputArguments");
            UaVariableNode prop = UaVariableNode.builder(getNodeContext())
                    .setNodeId(propId)
                    .setBrowseName(new QualifiedName(0, "InputArguments"))
                    .setDisplayName(LocalizedText.english("InputArguments"))
                    .setDataType(Identifiers.Argument)
                    .setTypeDefinition(Identifiers.PropertyType)
                    .setValueRank(1)
                    .setAccessLevel(ro)
                    .setUserAccessLevel(ro)
                    .build();
            prop.setValue(new DataValue(new Variant(inputArgs)));
            getNodeManager().addNode(prop);
            methodNode.addReference(new Reference(
                    methodNode.getNodeId(), Identifiers.HasProperty, prop.getNodeId().expanded(), true));
            prop.addReference(new Reference(
                    prop.getNodeId(), Identifiers.HasProperty, methodNode.getNodeId().expanded(), false));
        }
        if (outputArgs.length > 0) {
            NodeId propId = new NodeId(getNamespaceIndex(), id + ".OutputArguments");
            UaVariableNode prop = UaVariableNode.builder(getNodeContext())
                    .setNodeId(propId)
                    .setBrowseName(new QualifiedName(0, "OutputArguments"))
                    .setDisplayName(LocalizedText.english("OutputArguments"))
                    .setDataType(Identifiers.Argument)
                    .setTypeDefinition(Identifiers.PropertyType)
                    .setValueRank(1)
                    .setAccessLevel(ro)
                    .setUserAccessLevel(ro)
                    .build();
            prop.setValue(new DataValue(new Variant(outputArgs)));
            getNodeManager().addNode(prop);
            methodNode.addReference(new Reference(
                    methodNode.getNodeId(), Identifiers.HasProperty, prop.getNodeId().expanded(), true));
            prop.addReference(new Reference(
                    prop.getNodeId(), Identifiers.HasProperty, methodNode.getNodeId().expanded(), false));
        }
    }

    private void connectToParent(UaNode node, FixtureModel.NodeDef nd) {
        if (nd.parentNodeId == null) return;
        NodeId parentId  = resolveNodeId(nd.parentNodeId);
        NodeId refTypeId = getReferenceTypeId(nd.referenceType);

        Optional<UaNode> parentOpt = getNodeManager().getNode(parentId);
        if (!parentOpt.isPresent()) {
            parentOpt = getServer().getAddressSpaceManager().getManagedNode(parentId);
        }

        final NodeId childId = node.getNodeId();
        parentOpt.ifPresent(p -> p.addReference(
                new Reference(parentId, refTypeId, childId.expanded(), true)));

        node.addReference(new Reference(childId, refTypeId, parentId.expanded(), false));
    }

    // -------------------------------------------------------------------------
    // Behaviors
    // -------------------------------------------------------------------------

    private void setupBehaviors() {
        for (FixtureModel.BehaviorDef beh : fixture.behaviors) {
            UaNode target = nodeByFixtureId.get(beh.target);
            if (!(target instanceof UaVariableNode)) {
                LOG.warn("Behavior target not found or not a variable: {}", beh.target);
                continue;
            }
            scheduleBehavior((UaVariableNode) target, beh);
        }
    }

    private void scheduleBehavior(UaVariableNode node, FixtureModel.BehaviorDef beh) {
        switch (beh.kind) {
            case "counter": {
                long[] counter = { (long) beh.initial };
                long   inc     = (long) beh.increment;
                scheduler.scheduleAtFixedRate(() -> {
                    long val = counter[0];
                    counter[0] += inc;
                    node.setValue(new DataValue(new Variant(val)));
                }, 0, beh.intervalMs, TimeUnit.MILLISECONDS);
                break;
            }
            case "toggle": {
                boolean[] state = { false };
                scheduler.scheduleAtFixedRate(() -> {
                    state[0] = !state[0];
                    node.setValue(new DataValue(new Variant(state[0])));
                }, 0, beh.intervalMs, TimeUnit.MILLISECONDS);
                break;
            }
            case "ramp": {
                double[] ramp = { beh.initial };
                double inc = beh.increment, min = beh.minimum, max = beh.maximum;
                scheduler.scheduleAtFixedRate(() -> {
                    double val = ramp[0];
                    ramp[0] += inc;
                    if (ramp[0] > max) ramp[0] = min;
                    node.setValue(new DataValue(new Variant(val)));
                }, 0, beh.intervalMs, TimeUnit.MILLISECONDS);
                break;
            }
            default:
                LOG.warn("Unknown behavior kind: {}", beh.kind);
        }
    }

    // -------------------------------------------------------------------------
    // Method handlers
    // -------------------------------------------------------------------------

    private MethodInvocationHandler createMethodHandler(String behavior,
                                                          UaMethodNode methodNode,
                                                          Argument[] inArgs,
                                                          Argument[] outArgs) {
        if (behavior == null) return MethodInvocationHandler.NOT_IMPLEMENTED;

        switch (behavior) {
            case "Add":
                return new AbstractMethodInvocationHandler(methodNode) {
                    @Override public Argument[] getInputArguments()  { return inArgs; }
                    @Override public Argument[] getOutputArguments() { return outArgs; }
                    @Override
                    protected Variant[] invoke(
                            AbstractMethodInvocationHandler.InvocationContext ctx,
                            Variant[] inputs) throws UaException {
                        int a = ((Number) inputs[0].getValue()).intValue();
                        int b = ((Number) inputs[1].getValue()).intValue();
                        return new Variant[]{ new Variant(a + b) };
                    }
                };

            case "Multiply":
                return new AbstractMethodInvocationHandler(methodNode) {
                    @Override public Argument[] getInputArguments()  { return inArgs; }
                    @Override public Argument[] getOutputArguments() { return outArgs; }
                    @Override
                    protected Variant[] invoke(
                            AbstractMethodInvocationHandler.InvocationContext ctx,
                            Variant[] inputs) throws UaException {
                        double a = ((Number) inputs[0].getValue()).doubleValue();
                        double b = ((Number) inputs[1].getValue()).doubleValue();
                        return new Variant[]{ new Variant(a * b) };
                    }
                };

            case "Echo":
                return new AbstractMethodInvocationHandler(methodNode) {
                    @Override public Argument[] getInputArguments()  { return inArgs; }
                    @Override public Argument[] getOutputArguments() { return outArgs; }
                    @Override
                    protected Variant[] invoke(
                            AbstractMethodInvocationHandler.InvocationContext ctx,
                            Variant[] inputs) throws UaException {
                        String s = (String) inputs[0].getValue();
                        return new Variant[]{ new Variant(s) };
                    }
                };

            case "NoArguments":
                return new AbstractMethodInvocationHandler(methodNode) {
                    @Override public Argument[] getInputArguments()  { return inArgs; }
                    @Override public Argument[] getOutputArguments() { return outArgs; }
                    @Override
                    protected Variant[] invoke(
                            AbstractMethodInvocationHandler.InvocationContext ctx,
                            Variant[] inputs) throws UaException {
                        return new Variant[]{ new Variant(Boolean.TRUE) };
                    }
                };

            case "MultipleOutputs":
                return new AbstractMethodInvocationHandler(methodNode) {
                    @Override public Argument[] getInputArguments()  { return inArgs; }
                    @Override public Argument[] getOutputArguments() { return outArgs; }
                    @Override
                    protected Variant[] invoke(
                            AbstractMethodInvocationHandler.InvocationContext ctx,
                            Variant[] inputs) throws UaException {
                        int inp = ((Number) inputs[0].getValue()).intValue();
                        return new Variant[]{
                                new Variant(inp * 2),
                                new Variant(Integer.toString(inp))
                        };
                    }
                };

            case "Fail":
                return new AbstractMethodInvocationHandler(methodNode) {
                    @Override public Argument[] getInputArguments()  { return inArgs; }
                    @Override public Argument[] getOutputArguments() { return outArgs; }
                    @Override
                    protected Variant[] invoke(
                            AbstractMethodInvocationHandler.InvocationContext ctx,
                            Variant[] inputs) throws UaException {
                        throw new UaException(
                                org.eclipse.milo.opcua.stack.core.StatusCodes.Bad_InternalError,
                                "Method deliberately fails");
                    }
                };

            default:
                return MethodInvocationHandler.NOT_IMPLEMENTED;
        }
    }

    // -------------------------------------------------------------------------
    // Argument building
    // -------------------------------------------------------------------------

    private Argument[] buildArguments(List<FixtureModel.ArgumentDef> defs) {
        if (defs == null || defs.isEmpty()) return new Argument[0];
        Argument[] args = new Argument[defs.size()];
        for (int i = 0; i < defs.size(); i++) {
            FixtureModel.ArgumentDef d = defs.get(i);
            args[i] = new Argument(
                    d.name != null ? d.name : "",
                    getDataTypeId(d.dataType),
                    d.valueRank,
                    null,
                    LocalizedText.english(d.description != null ? d.description : ""));
        }
        return args;
    }

    // -------------------------------------------------------------------------
    // NodeId resolution
    // -------------------------------------------------------------------------

    public NodeId resolveNodeId(String nodeIdStr) {
        if (nodeIdStr == null) return NodeId.NULL_VALUE;

        if (nodeIdStr.startsWith("nsu=")) {
            int semi = nodeIdStr.indexOf(';', 4);
            if (semi < 0) return NodeId.NULL_VALUE;
            String uri  = nodeIdStr.substring(4, semi);
            String rest = nodeIdStr.substring(semi + 1);

            UShort idx   = getServer().getNamespaceTable().getIndex(uri);
            int nsIdx    = (idx != null) ? idx.intValue()
                    : (getNamespaceUri().equals(uri) ? getNamespaceIndex().intValue() : 1);

            if (rest.startsWith("s=")) return new NodeId(nsIdx, rest.substring(2));
            if (rest.startsWith("i=")) return new NodeId(nsIdx, UInteger.valueOf(rest.substring(2)));
            return NodeId.NULL_VALUE;
        }

        if (nodeIdStr.startsWith("ns=")) {
            int semi = nodeIdStr.indexOf(';');
            if (semi < 0) return NodeId.NULL_VALUE;
            int ns   = Integer.parseInt(nodeIdStr.substring(3, semi));
            String rest = nodeIdStr.substring(semi + 1);
            if (rest.startsWith("s=")) return new NodeId(ns, rest.substring(2));
            if (rest.startsWith("i=")) return new NodeId(ns, UInteger.valueOf(rest.substring(2)));
            return NodeId.NULL_VALUE;
        }

        if (nodeIdStr.startsWith("i=")) {
            return new NodeId(0, UInteger.valueOf(nodeIdStr.substring(2)));
        }

        return NodeId.NULL_VALUE;
    }

    private QualifiedName parseBrowseName(String s) {
        if (s == null) return new QualifiedName(getNamespaceIndex(), "");
        int colon = s.indexOf(':');
        if (colon >= 0) {
            try {
                int ns = Integer.parseInt(s.substring(0, colon));
                return new QualifiedName(ns, s.substring(colon + 1));
            } catch (NumberFormatException ignored) { }
        }
        return new QualifiedName(getNamespaceIndex(), s);
    }

    // -------------------------------------------------------------------------
    // Value conversion
    // -------------------------------------------------------------------------

    private Variant buildVariant(Object jsonValue, String dataType, int valueRank) {
        if (jsonValue == null) return Variant.NULL_VALUE;
        if (valueRank >= 1 && jsonValue instanceof List) {
            return buildArrayVariant((List<?>) jsonValue, dataType);
        }
        Object scalar = convertScalar(jsonValue, dataType);
        return scalar != null ? new Variant(scalar) : Variant.NULL_VALUE;
    }

    private Variant buildArrayVariant(List<?> list, String dataType) {
        if (list.isEmpty()) return new Variant(buildEmptyArray(dataType));
        switch (dataType != null ? dataType : "") {
            case "Boolean":  { Boolean[]  a = new Boolean[list.size()];  for (int i=0;i<list.size();i++) a[i]=(Boolean)convertScalar(list.get(i),dataType);   return new Variant(a); }
            case "SByte":    { Byte[]     a = new Byte[list.size()];     for (int i=0;i<list.size();i++) a[i]=(Byte)convertScalar(list.get(i),dataType);       return new Variant(a); }
            case "Byte":     { UByte[]    a = new UByte[list.size()];    for (int i=0;i<list.size();i++) a[i]=(UByte)convertScalar(list.get(i),dataType);      return new Variant(a); }
            case "Int16":    { Short[]    a = new Short[list.size()];    for (int i=0;i<list.size();i++) a[i]=(Short)convertScalar(list.get(i),dataType);      return new Variant(a); }
            case "UInt16":   { UShort[]   a = new UShort[list.size()];   for (int i=0;i<list.size();i++) a[i]=(UShort)convertScalar(list.get(i),dataType);    return new Variant(a); }
            case "Int32":    { Integer[]  a = new Integer[list.size()];  for (int i=0;i<list.size();i++) a[i]=(Integer)convertScalar(list.get(i),dataType);   return new Variant(a); }
            case "UInt32":   { UInteger[] a = new UInteger[list.size()]; for (int i=0;i<list.size();i++) a[i]=(UInteger)convertScalar(list.get(i),dataType);  return new Variant(a); }
            case "Int64":    { Long[]     a = new Long[list.size()];     for (int i=0;i<list.size();i++) a[i]=(Long)convertScalar(list.get(i),dataType);       return new Variant(a); }
            case "UInt64":   { ULong[]    a = new ULong[list.size()];    for (int i=0;i<list.size();i++) a[i]=(ULong)convertScalar(list.get(i),dataType);      return new Variant(a); }
            case "Float":    { Float[]    a = new Float[list.size()];    for (int i=0;i<list.size();i++) a[i]=(Float)convertScalar(list.get(i),dataType);      return new Variant(a); }
            case "Double":   { Double[]   a = new Double[list.size()];   for (int i=0;i<list.size();i++) a[i]=(Double)convertScalar(list.get(i),dataType);     return new Variant(a); }
            case "String":   { String[]   a = new String[list.size()];   for (int i=0;i<list.size();i++) a[i]=(String)convertScalar(list.get(i),dataType);     return new Variant(a); }
            case "ByteString":{ ByteString[] a = new ByteString[list.size()]; for (int i=0;i<list.size();i++) a[i]=(ByteString)convertScalar(list.get(i),dataType); return new Variant(a); }
            default: {
                Object[] a = new Object[list.size()];
                for (int i=0;i<list.size();i++) a[i]=convertScalar(list.get(i),dataType);
                return new Variant(a);
            }
        }
    }

    private Object buildEmptyArray(String dataType) {
        switch (dataType != null ? dataType : "") {
            case "Int32":  return new Integer[0];
            case "Double": return new Double[0];
            case "String": return new String[0];
            default:       return new Object[0];
        }
    }

    @SuppressWarnings("unchecked")
    private Object convertScalar(Object jsonValue, String dataType) {
        if (jsonValue == null) return null;
        try {
            switch (dataType != null ? dataType : "") {
                case "Boolean":
                    if (jsonValue instanceof Boolean) return jsonValue;
                    return Boolean.parseBoolean(jsonValue.toString());
                case "SByte":   return ((Number) jsonValue).byteValue();
                case "Byte":    return UByte.valueOf(((Number) jsonValue).intValue() & 0xFF);
                case "Int16":   return ((Number) jsonValue).shortValue();
                case "UInt16":  return UShort.valueOf(((Number) jsonValue).intValue() & 0xFFFF);
                case "Int32":   return ((Number) jsonValue).intValue();
                case "UInt32":  return UInteger.valueOf(((Number) jsonValue).longValue() & 0xFFFFFFFFL);
                case "Int64":
                    if (jsonValue instanceof String) return Long.parseLong((String) jsonValue);
                    return ((Number) jsonValue).longValue();
                case "UInt64":
                    if (jsonValue instanceof String) return ULong.valueOf((String) jsonValue);
                    return ULong.valueOf(((Number) jsonValue).longValue());
                case "Float":   return ((Number) jsonValue).floatValue();
                case "Double":  return ((Number) jsonValue).doubleValue();
                case "String":
                case "XmlElement": return jsonValue.toString();
                case "DateTime":   return parseDateTime(jsonValue.toString());
                case "Guid":       return UUID.fromString(jsonValue.toString());
                case "ByteString":
                    return new ByteString(Base64.getDecoder().decode(jsonValue.toString()));
                case "NodeId":       return resolveNodeId(jsonValue.toString());
                case "QualifiedName": return parseQualifiedName(jsonValue.toString());
                case "LocalizedText": return parseLocalizedText(jsonValue.toString());
                case "StatusCode":    return new StatusCode(((Number) jsonValue).longValue());
                default:             return jsonValue;
            }
        } catch (Exception e) {
            LOG.warn("convertScalar failed type={} value={}: {}", dataType, jsonValue, e.getMessage());
            return null;
        }
    }

    private DateTime parseDateTime(String s) {
        try { return new DateTime(Instant.parse(s).toEpochMilli()); }
        catch (Exception e) { return DateTime.NULL_VALUE; }
    }

    private QualifiedName parseQualifiedName(String s) {
        int colon = s.indexOf(':');
        if (colon >= 0) {
            try { return new QualifiedName(Integer.parseInt(s.substring(0, colon)), s.substring(colon + 1)); }
            catch (NumberFormatException ignored) { }
        }
        return new QualifiedName(0, s);
    }

    private LocalizedText parseLocalizedText(String s) {
        int colon = s.indexOf(':');
        if (colon >= 0) return new LocalizedText(s.substring(0, colon), s.substring(colon + 1));
        return LocalizedText.english(s);
    }

    // -------------------------------------------------------------------------
    // Lookup helpers
    // -------------------------------------------------------------------------

    private Set<AccessLevel> buildAccessLevels(List<String> levels) {
        EnumSet<AccessLevel> set = EnumSet.noneOf(AccessLevel.class);
        if (levels == null) return set;
        for (String s : levels) {
            switch (s) {
                case "CurrentRead":    set.add(AccessLevel.CurrentRead);    break;
                case "CurrentWrite":   set.add(AccessLevel.CurrentWrite);   break;
                case "HistoryRead":    set.add(AccessLevel.HistoryRead);    break;
                case "HistoryWrite":   set.add(AccessLevel.HistoryWrite);   break;
                case "SemanticChange": set.add(AccessLevel.SemanticChange); break;
                case "StatusWrite":    set.add(AccessLevel.StatusWrite);    break;
                case "TimestampWrite": set.add(AccessLevel.TimestampWrite); break;
            }
        }
        return set;
    }

    private NodeId getDataTypeId(String name) {
        if (name == null) return Identifiers.BaseDataType;
        switch (name) {
            case "Boolean":       return Identifiers.Boolean;
            case "SByte":         return Identifiers.SByte;
            case "Byte":          return Identifiers.Byte;
            case "Int16":         return Identifiers.Int16;
            case "UInt16":        return Identifiers.UInt16;
            case "Int32":         return Identifiers.Int32;
            case "UInt32":        return Identifiers.UInt32;
            case "Int64":         return Identifiers.Int64;
            case "UInt64":        return Identifiers.UInt64;
            case "Float":         return Identifiers.Float;
            case "Double":        return Identifiers.Double;
            case "String":        return Identifiers.String;
            case "DateTime":      return Identifiers.DateTime;
            case "Guid":          return Identifiers.Guid;
            case "ByteString":    return Identifiers.ByteString;
            case "XmlElement":    return Identifiers.XmlElement;
            case "NodeId":        return Identifiers.NodeId;
            case "QualifiedName": return Identifiers.QualifiedName;
            case "LocalizedText": return Identifiers.LocalizedText;
            case "StatusCode":    return Identifiers.StatusCode;
            default:              return Identifiers.BaseDataType;
        }
    }

    private NodeId getReferenceTypeId(String name) {
        if (name == null) return Identifiers.Organizes;
        switch (name) {
            case "Organizes":         return Identifiers.Organizes;
            case "HasComponent":      return Identifiers.HasComponent;
            case "HasProperty":       return Identifiers.HasProperty;
            case "HasSubtype":        return Identifiers.HasSubtype;
            case "HasTypeDefinition": return Identifiers.HasTypeDefinition;
            case "Aggregates":        return Identifiers.Aggregates;
            default:                  return Identifiers.Organizes;
        }
    }

    @Override
    public void onDataItemsCreated(List<DataItem> dataItems) {
        subscriptionModel.onDataItemsCreated(dataItems);
    }

    @Override
    public void onDataItemsModified(List<DataItem> dataItems) {
        subscriptionModel.onDataItemsModified(dataItems);
    }

    @Override
    public void onDataItemsDeleted(List<DataItem> dataItems) {
        subscriptionModel.onDataItemsDeleted(dataItems);
    }

    @Override
    public void onMonitoringModeChanged(List<MonitoredItem> monitoredItems) {
        subscriptionModel.onMonitoringModeChanged(monitoredItems);
    }
}
