package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;

import java.util.Base64;
import java.util.UUID;

/** Parses NodeId strings per CLIENT_CONTRACT §8. */
public class NodeIdParser {

    /** Exception thrown for invalid/unresolvable NodeId input. Exits code 2. */
    public static class InvalidNodeIdException extends Exception {
        public InvalidNodeIdException(String msg) { super(msg); }
    }

    /** Exception thrown when a namespace URI is not found. Exits code 2. */
    public static class UnknownNamespaceException extends Exception {
        public UnknownNamespaceException(String uri) {
            super("unknown namespace URI: " + uri);
        }
    }

    /**
     * Parse a NodeId string without namespace resolution (no client needed).
     * Handles: i=N, ns=N;i=N, ns=N;s=name, ns=N;g=UUID, ns=N;b=base64.
     * For nsu= forms, use resolveWithClient().
     */
    public static NodeId parse(String s) throws InvalidNodeIdException {
        if (s == null || s.isEmpty()) throw new InvalidNodeIdException("empty NodeId");
        try {
            if (s.startsWith("nsu=")) {
                throw new InvalidNodeIdException("nsu= form requires client for namespace resolution: " + s);
            }
            if (s.startsWith("i=")) {
                return new NodeId(0, UInteger.valueOf(s.substring(2)));
            }
            if (s.startsWith("ns=")) {
                int semi = s.indexOf(';');
                if (semi < 0) throw new InvalidNodeIdException("missing ';' in NodeId: " + s);
                int ns = Integer.parseInt(s.substring(3, semi));
                String rest = s.substring(semi + 1);
                return parseIdentifier(ns, rest, s);
            }
            throw new InvalidNodeIdException("unrecognized NodeId form: " + s);
        } catch (NumberFormatException e) {
            throw new InvalidNodeIdException("malformed NodeId: " + s);
        }
    }

    /**
     * Parse a NodeId, resolving nsu= namespace URIs using the connected client.
     */
    public static NodeId resolveWithClient(String s, OpcUaClient client, long requestTimeoutMs)
            throws InvalidNodeIdException, UnknownNamespaceException, Exception {
        if (s == null || s.isEmpty()) throw new InvalidNodeIdException("empty NodeId");
        if (s.startsWith("nsu=")) {
            int semi = s.indexOf(';', 4);
            if (semi < 0) throw new InvalidNodeIdException("malformed nsu= NodeId (missing ';'): " + s);
            String uri = s.substring(4, semi);
            String rest = s.substring(semi + 1);
            int nsIdx = lookupNamespaceIndex(client, uri, requestTimeoutMs);
            if (nsIdx < 0) throw new UnknownNamespaceException(uri);
            return parseIdentifier(nsIdx, rest, s);
        }
        return parse(s);
    }

    private static NodeId parseIdentifier(int ns, String rest, String original)
            throws InvalidNodeIdException {
        if (rest.startsWith("s=")) return new NodeId(ns, rest.substring(2));
        if (rest.startsWith("i=")) {
            try {
                return new NodeId(ns, UInteger.valueOf(rest.substring(2)));
            } catch (NumberFormatException e) {
                throw new InvalidNodeIdException("malformed numeric NodeId: " + original);
            }
        }
        if (rest.startsWith("g=")) {
            try {
                return new NodeId(ns, UUID.fromString(rest.substring(2)));
            } catch (IllegalArgumentException e) {
                throw new InvalidNodeIdException("malformed GUID NodeId: " + original);
            }
        }
        if (rest.startsWith("b=")) {
            try {
                byte[] bytes = Base64.getDecoder().decode(rest.substring(2));
                return new NodeId(ns, ByteString.of(bytes));
            } catch (IllegalArgumentException e) {
                throw new InvalidNodeIdException("malformed ByteString NodeId: " + original);
            }
        }
        throw new InvalidNodeIdException("unrecognized identifier form in NodeId: " + original);
    }

    private static int lookupNamespaceIndex(OpcUaClient client, String uri, long timeoutMs)
            throws Exception {
        DataValue dv = client.readValue(0.0, TimestampsToReturn.Neither,
                Identifiers.Server_NamespaceArray);
        if (dv.getValue() != null && dv.getValue().getValue() instanceof String[]) {
            String[] ns = (String[]) dv.getValue().getValue();
            for (int i = 0; i < ns.length; i++) {
                if (uri.equals(ns[i])) return i;
            }
        }
        return -1;
    }
}
