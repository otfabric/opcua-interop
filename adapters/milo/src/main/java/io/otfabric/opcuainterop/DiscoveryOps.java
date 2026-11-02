package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.stack.core.Stack;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.UaServiceFaultException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.UaRequestMessageType;
import org.eclipse.milo.opcua.stack.core.types.UaResponseMessageType;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.FindServersOnNetworkRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.FindServersOnNetworkResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.MdnsDiscoveryConfiguration;
import org.eclipse.milo.opcua.stack.core.types.structured.RegisterServer2Request;
import org.eclipse.milo.opcua.stack.core.types.structured.RegisterServer2Response;
import org.eclipse.milo.opcua.stack.core.types.structured.RegisterServerRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.RegisteredServer;
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransport;
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransportConfig;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

/**
 * Discovery service set calls against a Local Discovery Server, on a
 * SecureChannel (SecurityPolicy None) without a Session.
 *
 * Milo's SDK ships {@link DiscoveryClient#registerServer}; RegisterServer2 and
 * FindServersOnNetwork are sent as plain request messages on the same
 * transport.
 */
final class DiscoveryOps {

    private DiscoveryOps() {}

    /** An open discovery channel. */
    static final class Channel implements AutoCloseable {
        final DiscoveryClient client;
        final OpcTcpClientTransport transport;

        Channel(DiscoveryClient client, OpcTcpClientTransport transport) {
            this.client = client;
            this.transport = transport;
        }

        @Override
        public void close() {
            try {
                client.disconnectAsync().get(2, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // best effort
            }
        }
    }

    /** Result of a registration attempt. */
    static final class RegisterResult {
        String service;              // service whose result counts
        StatusCode status = StatusCode.GOOD;
        StatusCode registerServer2Status; // null when RegisterServer2 was not tried
        boolean fallback;
        StatusCode[] configurationResults = new StatusCode[0];

        boolean ok() {
            if (!status.isGood()) return false;
            for (StatusCode c : configurationResults) {
                if (c != null && !c.isGood()) return false;
            }
            return true;
        }
    }

    static Channel open(String url, long timeoutMs) throws Exception {
        EndpointDescription endpoint = new EndpointDescription(
            url, null, null, MessageSecurityMode.None, SecurityPolicy.None.getUri(), null,
            Stack.TCP_UASC_UABINARY_TRANSPORT_URI, ubyte(0));
        OpcTcpClientTransport transport =
            new OpcTcpClientTransport(OpcTcpClientTransportConfig.newBuilder().build());
        DiscoveryClient client = new DiscoveryClient(endpoint, transport);
        try {
            client.connectAsync().get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            throw new UaException(StatusCodes.Bad_ConnectionRejected, e.getCause());
        }
        return new Channel(client, transport);
    }

    /** Sends a request; a ServiceFault is returned as its status code. */
    private static Object send(Channel ch, UaRequestMessageType request, long timeoutMs) throws Exception {
        try {
            UaResponseMessageType resp =
                ch.transport.sendRequestMessage(request).get(timeoutMs, TimeUnit.MILLISECONDS);
            return resp;
        } catch (ExecutionException e) {
            for (Throwable c = e.getCause(); c != null; c = c.getCause()) {
                if (c instanceof UaServiceFaultException f) return f.getStatusCode();
                if (c instanceof UaException u) return u.getStatusCode();
            }
            throw e;
        }
    }

    static boolean unsupported(StatusCode sc) {
        long v = sc.getValue();
        return v == StatusCodes.Bad_ServiceUnsupported
            || v == StatusCodes.Bad_NotImplemented
            || v == StatusCodes.Bad_NotSupported;
    }

    /**
     * @param service {@code auto} (RegisterServer2, falling back to RegisterServer when the
     *     LDS does not implement it), {@code RegisterServer2} or {@code RegisterServer}.
     */
    static RegisterResult register(Channel ch, RegisteredServer server, String mdnsName,
                                   String[] capabilities, String service, long timeoutMs) throws Exception {
        RegisterResult out = new RegisterResult();
        boolean want2 = "auto".equals(service) || "RegisterServer2".equals(service);
        boolean want1 = "auto".equals(service) || "RegisterServer".equals(service);
        UInteger timeout = uint(timeoutMs);

        if (want2) {
            MdnsDiscoveryConfiguration mdns = new MdnsDiscoveryConfiguration(mdnsName, capabilities);
            ExtensionObject cfg = ExtensionObject.encode(DefaultEncodingContext.INSTANCE, mdns);
            RegisterServer2Request req = new RegisterServer2Request(
                ch.client.newRequestHeader(NodeId.NULL_VALUE, timeout), server, new ExtensionObject[] {cfg});
            Object resp = send(ch, req, timeoutMs);
            out.service = "RegisterServer2";
            if (resp instanceof RegisterServer2Response r2) {
                out.status = r2.getResponseHeader().getServiceResult();
                if (r2.getConfigurationResults() != null) out.configurationResults = r2.getConfigurationResults();
            } else {
                out.status = (StatusCode) resp;
            }
            out.registerServer2Status = out.status;
        }

        if (want1 && (!want2 || unsupported(out.status))) {
            RegisterServerRequest req = new RegisterServerRequest(
                ch.client.newRequestHeader(NodeId.NULL_VALUE, timeout), server);
            Object resp = send(ch, req, timeoutMs);
            out.fallback = want2;
            out.service = "RegisterServer";
            out.configurationResults = new StatusCode[0];
            out.status = (resp instanceof StatusCode sc) ? sc : StatusCode.GOOD;
            if (resp instanceof UaResponseMessageType r) out.status = r.getResponseHeader().getServiceResult();
        }
        return out;
    }

    /** Returns the response, or the service fault's status code. */
    static Object findServersOnNetwork(Channel ch, long startingRecordId, long maxRecords,
                                       String[] capabilityFilter, long timeoutMs) throws Exception {
        FindServersOnNetworkRequest req = new FindServersOnNetworkRequest(
            ch.client.newRequestHeader(NodeId.NULL_VALUE, uint(timeoutMs)),
            uint(startingRecordId), uint(maxRecords),
            capabilityFilter != null && capabilityFilter.length > 0 ? capabilityFilter : null);
        Object resp = send(ch, req, timeoutMs);
        if (resp instanceof FindServersOnNetworkResponse) return resp;
        return resp;
    }
}
