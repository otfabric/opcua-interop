// SPDX-License-Identifier: MIT
//
// Unit tests of the contract helpers (§3, §5-§7, §12). Run in the image build.

import assert from "node:assert/strict";
import { test } from "node:test";

import { DataType, NodeId, NodeIdType, StatusCodes, Variant, VariantArrayType } from "node-opcua";

import {
    Args,
    bigToInt64,
    buildVariant,
    buildVariantLenient,
    dataValueJson,
    float32Number,
    InputError,
    nodeIdToString,
    parseNodeIdString,
    resolveParsed,
    Result,
    scalarJson,
    severityOf,
    statusFromError,
    statusJson,
    statusName,
    variantValueJson,
} from "./util.js";

test("parseNodeIdString: the four identifier types, ns and nsu", () => {
    assert.deepEqual(parseNodeIdString("i=85"), { nsu: undefined, ns: 0, type: NodeIdType.NUMERIC, value: 85 });
    assert.deepEqual(parseNodeIdString("ns=3;s=A.B"), { nsu: undefined, ns: 3, type: NodeIdType.STRING, value: "A.B" });
    const g = parseNodeIdString("ns=1;g=09087e75-8e5e-499b-954f-f2a9603db28a");
    assert.equal(g.type, NodeIdType.GUID);
    assert.equal(g.value, "09087E75-8E5E-499B-954F-F2A9603DB28A");
    const b = parseNodeIdString("ns=1;b=AQID");
    assert.equal(b.type, NodeIdType.BYTESTRING);
    assert.deepEqual(b.value, Buffer.from([1, 2, 3]));
    assert.equal(parseNodeIdString("nsu=urn:x;s=Y").nsu, "urn:x");
});

test("parseNodeIdString: malformed input is an input error", () => {
    for (const s of ["", "x=1", "i=abc", "ns=70000;i=1", "ns=1", "nsu=;s=x", "s=", "g=not-a-guid", "i=4294967296"]) {
        assert.throws(() => parseNodeIdString(s), InputError, s);
    }
});

test("resolveParsed: nsu is resolved against the NamespaceArray", () => {
    const n = resolveParsed(parseNodeIdString("nsu=urn:b;s=X"), ["http://opcfoundation.org/UA/", "urn:a", "urn:b"]);
    assert.equal(n.namespace, 2);
    assert.throws(() => resolveParsed(parseNodeIdString("nsu=urn:missing;s=X"), ["urn:a"]), InputError);
});

test("nodeIdToString: canonical form (§6)", () => {
    assert.equal(nodeIdToString(new NodeId(NodeIdType.NUMERIC, 2253, 0)), "i=2253");
    assert.equal(nodeIdToString(new NodeId(NodeIdType.NUMERIC, 7, 2)), "ns=2;i=7");
    assert.equal(nodeIdToString(new NodeId(NodeIdType.STRING, "Scalar.Int32", 2)), "ns=2;s=Scalar.Int32");
    assert.equal(nodeIdToString(new NodeId(NodeIdType.STRING, "x", 0)), "ns=0;s=x");
    assert.equal(nodeIdToString(new NodeId(NodeIdType.GUID, "09087E75-8E5E-499B-954F-F2A9603DB28A", 1)), "ns=1;g=09087e75-8e5e-499b-954f-f2a9603db28a");
});

test("status codes: names, severities, the contract JSON", () => {
    assert.equal(statusName(0), "Good");
    assert.equal(statusName(StatusCodes.BadNodeIdUnknown.value), "BadNodeIdUnknown");
    assert.equal(severityOf(0x40000000), "Uncertain");
    assert.equal(severityOf(0x80000000), "Bad");
    assert.deepEqual(statusJson(StatusCodes.BadTypeMismatch), { name: "BadTypeMismatch", code: 0x80740000, severity: "Bad" });
    // Info bits do not hide the name.
    assert.equal(statusName((StatusCodes.Good.value | 0x480) >>> 0), "Good");
    assert.equal(statusFromError(new Error("The connection may have been rejected: BadSecurityChecksFailed")), StatusCodes.BadSecurityChecksFailed.value);
    assert.equal(statusFromError(new Error("status 0x80340000")), 0x80340000);
    assert.equal(statusFromError(new Error("nothing")), undefined);
});

test("Int64 / UInt64 round-trip through node-opcua's [hi, lo] form", () => {
    const max = (1n << 63n) - 1n;
    assert.equal(scalarJson(DataType.Int64, bigToInt64(max)), max.toString());
    assert.equal(scalarJson(DataType.Int64, bigToInt64(-(1n << 63n))), (-(1n << 63n)).toString());
    assert.equal(scalarJson(DataType.Int64, bigToInt64(-1n)), "-1");
    assert.equal(scalarJson(DataType.UInt64, bigToInt64((1n << 64n) - 1n)), "18446744073709551615");
});

test("float32Number: shortest decimal that reads back as the same float", () => {
    assert.equal(float32Number(Math.fround(3.14)), 3.14);
    assert.equal(float32Number(Math.fround(0.1)), 0.1);
    assert.equal(float32Number(NaN), null);
});

test("buildVariant: §12 literals, strict", () => {
    assert.deepEqual(buildVariant("Int32", "-5").value, -5);
    assert.equal(buildVariant("Boolean", "true").value, true);
    assert.equal(buildVariant("Double", "NaN").value, NaN);
    const arr = buildVariant("Int32[]", "1,2,3");
    assert.equal(arr.arrayType, VariantArrayType.Array);
    assert.deepEqual([...(arr.value as number[])], [1, 2, 3]);
    assert.deepEqual(buildVariant("Int64", "-1").value, [0xffffffff, 0xffffffff]);
    assert.throws(() => buildVariant("Int32", "2147483648"), InputError);
    assert.throws(() => buildVariant("Byte", "-1"), InputError);
    assert.throws(() => buildVariant("Boolean", "yes"), InputError);
    assert.throws(() => buildVariant("NoSuchType", "1"), InputError);
    assert.throws(() => buildVariant("Guid", "x"), InputError);
});

test("buildVariantLenient: write / call send a bad literal as String (§12)", () => {
    const v = buildVariantLenient("Int32", "not-a-number");
    assert.equal(v.dataType, DataType.String);
    assert.equal(v.value, "not-a-number");
});

test("variantValueJson / dataValueJson: canonical values (§7)", () => {
    assert.deepEqual(variantValueJson(new Variant({ dataType: DataType.ByteString, value: Buffer.from("hi") })), "aGk=");
    assert.equal(variantValueJson(new Variant({ dataType: DataType.Null })), null);
    assert.deepEqual(variantValueJson(new Variant({ dataType: DataType.Int32, arrayType: VariantArrayType.Array, value: [1, 2] })), [1, 2]);
    const m = new Variant({ dataType: DataType.Int32, arrayType: VariantArrayType.Matrix, dimensions: [3, 2], value: [1, 2, 3, 4, 5, 6] });
    const dv = dataValueJson({ value: m, statusCode: StatusCodes.Good } as never);
    assert.deepEqual(dv.arrayDimensions, [3, 2]);
    assert.deepEqual(dv.value, [1, 2, 3, 4, 5, 6]);
    assert.equal(scalarJson(DataType.DateTime, new Date("2026-07-24T10:00:00Z")), "2026-07-24T10:00:00.000Z");
});

test("Args: last value wins, repeated flags, typed accessors", () => {
    const a = new Args(["--node", "a", "--node", "b", "--n", "3", "--flag", "false"]);
    assert.equal(a.get("--node"), "b");
    assert.deepEqual(a.all("--node"), ["a", "b"]);
    assert.equal(a.num("--n", 0), 3);
    assert.equal(a.bool("--flag", true), false);
    assert.throws(() => new Args(["--n", "x"]).num("--n", 0), InputError);
});

test("Result: the envelope (§3)", () => {
    const ok = new Result("read").toJSON();
    assert.equal(ok.adapter, "node-opcua");
    assert.equal(ok.error, null);
    const bad = new Result("read").setService(StatusCodes.BadTimeout).fail("timeout", "x").toJSON();
    assert.equal(bad.success, false);
    assert.deepEqual(bad.error, { category: "timeout", message: "x" });
    assert.deepEqual(Object.keys(bad), ["schemaVersion", "adapter", "operation", "success", "serviceResult", "results", "error"]);
});
