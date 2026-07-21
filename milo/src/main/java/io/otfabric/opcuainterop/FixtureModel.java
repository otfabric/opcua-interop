package io.otfabric.opcuainterop;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class FixtureModel {

    @JsonProperty("schemaVersion")  public String schemaVersion;
    @JsonProperty("id")             public String id;
    @JsonProperty("description")    public String description;
    @JsonProperty("server")         public ServerInfo server;
    @JsonProperty("endpoint")       public EndpointInfo endpoint;
    @JsonProperty("namespaces")     public List<NamespaceInfo> namespaces  = new ArrayList<>();
    @JsonProperty("nodes")          public List<NodeDef>       nodes       = new ArrayList<>();
    @JsonProperty("behaviors")      public List<BehaviorDef>   behaviors   = new ArrayList<>();
    @JsonProperty("methods")        public List<MethodDef>     methods     = new ArrayList<>();

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ServerInfo {
        public String applicationUri;
        public String productUri;
        public String applicationName;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class EndpointInfo {
        public String path  = "/";
        public int    port  = 4840;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class NamespaceInfo {
        public String alias;
        public String uri;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class NodeDef {
        public String       nodeClass;
        public String       nodeId;
        public String       browseName;
        public String       displayName;
        public String       description;
        public String       parentNodeId;
        public String       referenceType;
        public String       typeDefinition;

        // Variable fields
        public String       dataType;
        public int          valueRank = -1;
        @JsonProperty("accessLevel")
        public List<String> accessLevel = new ArrayList<>();
        @JsonProperty("initialValue")
        public Object       value;

        // Method fields
        public String            methodBehavior;
        public List<ArgumentDef> inputArguments  = new ArrayList<>();
        public List<ArgumentDef> outputArguments = new ArrayList<>();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class BehaviorDef {
        public String target;
        public String kind;
        public double initial;
        public double increment = 1.0;
        public double minimum;
        public double maximum   = 100.0;
        public long   intervalMs = 250;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MethodDef {
        public String            nodeId;
        public String            parentNodeId;
        public String            browseName;
        public String            displayName;
        public String            description;
        public String            method;
        public List<ArgumentDef> inputArguments  = new ArrayList<>();
        public List<ArgumentDef> outputArguments = new ArrayList<>();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ArgumentDef {
        public String name;
        public String dataType;
        public String description;
        public int    valueRank = -1;
    }
}
