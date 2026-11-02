import json, os, sys, base64
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
NS = "nsu=urn:otfabric:opcua-interop:model;s="
UDP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"
MQTT_UADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp"
MQTT_JSON = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json"
AES256 = "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"

# (field name, built-in type, DataType NodeId, valueRank, published node, target node)
FIELDS = [
    ("Boolean",     1,  "i=1",  -1, "PubSub.Boolean",     "PubSub.Boolean"),
    ("Int32",       6,  "i=6",  -1, "PubSub.Int32",       "PubSub.Int32"),
    ("Counter",     8,  "i=8",  -1, "Dynamic.Counter",    "PubSub.Int64"),
    ("UInt64",      9,  "i=9",  -1, "PubSub.UInt64",      "PubSub.UInt64"),
    ("Double",      11, "i=11", -1, "PubSub.Double",      "PubSub.Double"),
    ("String",      12, "i=12", -1, "PubSub.String",      "PubSub.String"),
    ("DateTime",    13, "i=13", -1, "PubSub.DateTime",    "PubSub.DateTime"),
    ("ByteString",  15, "i=15", -1, "PubSub.ByteString",  "PubSub.ByteString"),
    ("Int32Array",  6,  "i=6",   1, "PubSub.Int32Array",  "PubSub.Int32Array"),
    ("DoubleArray", 11, "i=11",  1, "PubSub.DoubleArray", "PubSub.DoubleArray"),
]

def eo(type_id, body):
    return {"UaTypeId": type_id, "UaBody": body}

def metadata():
    return {"Name": "InteropDataSet",
            "Fields": [{"Name": n, "BuiltInType": b, "DataType": d, "ValueRank": r}
                       for n, b, d, r, _, _ in FIELDS],
            "ConfigurationVersion": {"MajorVersion": 1, "MinorVersion": 1}}

def pds():
    return {"Name": "InteropDataSet",
            "DataSetMetaData": metadata(),
            "DataSetSource": eo("i=15581", {"PublishedData": [
                {"PublishedVariable": NS + p, "AttributeId": 13} for _, _, _, _, p, _ in FIELDS]})}

def uadp_wg_settings():
    # PublisherId | GroupHeader | WriterGroupId | SequenceNumber | PayloadHeader | Timestamp
    return eo("i=15645", {"NetworkMessageContentMask": 1 | 2 | 4 | 32 | 64 | 128})

def uadp_dsw_settings():
    # Timestamp | Status | MajorVersion | MinorVersion | SequenceNumber
    return eo("i=15652", {"DataSetMessageContentMask": 1 | 4 | 8 | 16 | 32})

def json_wg_settings():
    # NetworkMessageHeader | DataSetMessageHeader | PublisherId
    return eo("i=15657", {"NetworkMessageContentMask": 1 | 2 | 8})

def json_dsw_settings():
    # DataSetWriterId | MetaDataVersion | SequenceNumber | Timestamp | Status | MessageType
    return eo("i=15664", {"DataSetMessageContentMask": 1 | 2 | 4 | 8 | 16 | 32})

def publisher(url, profile, encoding="uadp", queue=None, writer_group_transport=None,
              security=None, interval=100):
    wg = {"Name": "InteropWriterGroup", "Enabled": True, "WriterGroupId": 100,
          "PublishingInterval": interval, "KeepAliveTime": 1000,
          "MessageSettings": uadp_wg_settings() if encoding == "uadp" else json_wg_settings(),
          "DataSetWriters": [{"Name": "InteropWriter", "Enabled": True, "DataSetWriterId": 1,
                              "DataSetName": "InteropDataSet", "KeyFrameCount": 1,
                              "DataSetFieldContentMask": 0,
                              "MessageSettings": uadp_dsw_settings() if encoding == "uadp" else json_dsw_settings()}]}
    if queue is not None:
        wg["TransportSettings"] = eo("i=15667", {"QueueName": queue})
    if writer_group_transport is not None:
        wg["TransportSettings"] = writer_group_transport
    if security:
        wg["SecurityMode"] = security["mode"]
        wg["SecurityGroupId"] = security["group"]
    conn = {"Name": "InteropPublisher", "Enabled": True,
            "PublisherId": {"UaType": 5, "Value": 2234},
            "TransportProfileUri": profile,
            "Address": eo("i=15510", {"Url": url}),
            "WriterGroups": [wg]}
    return {"PublishedDataSets": [pds()], "Connections": [conn], "Enabled": True}

def subscriber(url, profile, encoding="uadp", queue=None, security=None, timeout=0):
    dsr = {"Name": "InteropReader", "Enabled": True,
           "PublisherId": {"UaType": 5, "Value": 2234},
           "WriterGroupId": 100, "DataSetWriterId": 1,
           "DataSetMetaData": metadata(),
           "MessageReceiveTimeout": timeout,
           "SubscribedDataSet": eo("i=15631", {"TargetVariables": [
               {"TargetNodeId": NS + t, "AttributeId": 13} for _, _, _, _, _, t in FIELDS]})}
    if encoding == "json":
        dsr["MessageSettings"] = eo("i=15665", {"NetworkMessageContentMask": 1 | 2 | 8,
                                                "DataSetMessageContentMask": 1 | 2 | 4 | 8 | 16 | 32})
    else:
        dsr["MessageSettings"] = eo("i=15653", {"NetworkMessageContentMask": 1 | 2 | 4 | 32 | 64 | 128,
                                                "DataSetMessageContentMask": 1 | 4 | 8 | 16 | 32})
    if queue is not None:
        dsr["TransportSettings"] = eo("i=15670", {"QueueName": queue})
    rg = {"Name": "InteropReaderGroup", "Enabled": True, "DataSetReaders": [dsr]}
    if security:
        rg["SecurityMode"] = security["mode"]
        rg["SecurityGroupId"] = security["group"]
    conn = {"Name": "InteropSubscriber", "Enabled": True,
            "PublisherId": {"UaType": 5, "Value": 2235},
            "TransportProfileUri": profile,
            "Address": eo("i=15510", {"Url": url}),
            "ReaderGroups": [rg]}
    return {"Connections": [conn], "Enabled": True}

def write(name, doc):
    with open(os.path.join(out, name), "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

# Deterministic test key material: signingKey(32) | encryptingKey(32) | keyNonce(4)
key = bytes(range(1, 33)) + bytes(range(101, 133)) + bytes([0xA1, 0xA2, 0xA3, 0xA4])
GROUP = {"securityGroupId": "InteropGroup", "securityPolicyUri": AES256,
         "keyLifetimeMs": 60000, "maxFutureKeyCount": 2, "maxPastKeyCount": 1}
SEC = {"mode": 3, "group": "InteropGroup"}

def dg(url):
    # DatagramWriterGroupTransport2DataType with the unicast destination
    return eo("i=23613", {"Address": eo("i=15510", {"Url": url})})

write("udp-unicast-publisher.json", {"configuration": publisher("opc.udp://localhost:4840", UDP,
      writer_group_transport=dg("opc.udp://pubsub-subscriber:4841"))})
write("udp-unicast-subscriber.json", {"configuration": subscriber("opc.udp://0.0.0.0:4841", UDP)})
write("udp-multicast-publisher.json", {"configuration": publisher("opc.udp://224.0.0.22:4840", UDP)})
write("udp-multicast-subscriber.json", {"configuration": subscriber("opc.udp://224.0.0.22:4840", UDP)})
write("mqtt-uadp-publisher.json", {"configuration": publisher("mqtt://mosquitto:1883", MQTT_UADP, queue="opcua-interop/uadp")})
write("mqtt-uadp-subscriber.json", {"configuration": subscriber("mqtt://mosquitto:1883", MQTT_UADP, queue="opcua-interop/uadp")})
write("mqtt-json-publisher.json", {"configuration": publisher("mqtt://mosquitto:1883", MQTT_JSON, encoding="json", queue="opcua-interop/json")})
write("mqtt-json-subscriber.json", {"configuration": subscriber("mqtt://mosquitto:1883", MQTT_JSON, encoding="json", queue="opcua-interop/json")})
g = dict(GROUP); g["keys"] = [{"tokenId": 1, "key": base64.b64encode(key).decode()}]
write("udp-secure-publisher.json", {"configuration": publisher("opc.udp://localhost:4840", UDP, security=SEC,
      writer_group_transport=dg("opc.udp://pubsub-subscriber:4841")), "securityGroups": [g]})
write("udp-secure-subscriber.json", {"configuration": subscriber("opc.udp://0.0.0.0:4841", UDP, security=SEC), "securityGroups": [g]})
# SKS: the publisher is also the Security Key Service; the subscriber pulls the keys
write("sks-publisher.json", {"configuration": publisher("opc.udp://localhost:4840", UDP, security=SEC,
      writer_group_transport=dg("opc.udp://pubsub-subscriber:4841")),
                             "securityGroups": [dict(GROUP)], "serveSks": True})
write("sks-subscriber.json", {"configuration": subscriber("opc.udp://0.0.0.0:4841", UDP, security=SEC),
                              "securityGroups": [dict(GROUP)],
                              "sksClient": {"endpointUrl": "opc.tcp://pubsub-publisher:4840/opcua-interop",
                                            "securityPolicyUri": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                                            "securityMode": "SignAndEncrypt",
                                            "username": "test-user", "password": "test-password"}})
# SKS push: the subscriber has the group without keys; an SKS (here the smoke
# test's client) pushes the static key of udp-secure-publisher.json with
# SetSecurityKeys on a SignAndEncrypt session.
write("sks-push-subscriber.json", {"configuration": subscriber("opc.udp://0.0.0.0:4841", UDP, security=SEC),
                                   "securityGroups": [dict(GROUP)]})
