// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;

namespace OpcUaInterop
{
    /// <summary>The flags of client push (docs/CONTAINER_CONTRACT.md §1 "push flags"), validated before connecting.</summary>
    internal sealed class PushOptions
    {
        /// <summary>--group: the CertificateGroup (Part 12 §7.8.4) and its default CertificateType.</summary>
        private static readonly Dictionary<string, (uint Group, uint Type)> s_groups = new()
        {
            ["Application"] = (14156, 12560),
            ["Https"] = (14088, 12558),
            ["UserToken"] = (14122, 15181)
        };

        public string GroupId { get; private set; }
        public string CertificateTypeId { get; private set; }
        public byte[] Add { get; private set; }
        public string Remove { get; private set; }
        public bool Issuer { get; private set; }
        public bool GetCertificates { get; private set; }
        public bool SelfSigned { get; private set; }
        public string Subject { get; private set; }
        public List<string> Dns { get; private set; }
        public List<string> Ip { get; private set; }
        public ushort LifetimeDays { get; private set; }
        public ushort KeySize { get; private set; }
        public string DeleteType { get; private set; }
        public byte[] Update { get; private set; }
        public List<byte[]> Issuers { get; } = [];
        public string KeyFormat { get; private set; } = string.Empty;
        public byte[] Key { get; private set; }
        public bool Csr { get; private set; }
        public bool Reset { get; private set; }
        public bool Apply { get; private set; }
        public bool Cancel { get; private set; }
        public bool Diagnostics { get; private set; }

        public static PushOptions Parse(Args a)
        {
            var o = new PushOptions();
            string group = a.Get("--group") ?? "Application";
            if (!s_groups.TryGetValue(group, out (uint Group, uint Type) g))
            {
                throw new InputException("--group must be Application, Https or UserToken, got " + group);
            }
            o.GroupId = "i=" + g.Group.ToString(Inv.C);
            o.CertificateTypeId = NodeIdArg(a.Get("--certificate-type-id") ?? "i=" + g.Type.ToString(Inv.C), "--certificate-type-id");
            string add = a.Get("--add-certificate");
            if (add != null)
            {
                o.Add = CertificateDer(add, "--add-certificate");
            }
            o.Remove = a.Get("--remove-certificate");
            o.Issuer = a.Has("--issuer");
            o.GetCertificates = a.Has("--get-certificates");
            o.SelfSigned = a.Has("--create-self-signed");
            o.Subject = a.Get("--subject") ?? string.Empty;
            o.Dns = a.All("--dns");
            o.Ip = a.All("--ip");
            o.LifetimeDays = UInt16Arg(a, "--lifetime-days", 365);
            o.KeySize = UInt16Arg(a, "--key-size", 0);
            string del = a.Get("--delete-certificate");
            if (del != null)
            {
                o.DeleteType = NodeIdArg(del, "--delete-certificate");
            }
            string updateFile = a.Get("--update-certificate");
            string keyFile = a.Get("--update-private-key");
            if (keyFile != null && updateFile == null)
            {
                throw new InputException("--update-private-key needs --update-certificate");
            }
            if (updateFile != null)
            {
                o.Update = CertificateDer(updateFile, "--update-certificate");
            }
            foreach (string f in a.All("--issuer-certificate"))
            {
                o.Issuers.Add(CertificateDer(f, "--issuer-certificate"));
            }
            if (keyFile != null)
            {
                string fmt = a.Get("--private-key-format");
                if (fmt == null)
                {
                    string lower = keyFile.ToLowerInvariant();
                    fmt = lower.EndsWith(".pfx", StringComparison.Ordinal) || lower.EndsWith(".p12", StringComparison.Ordinal) ? "PFX" : "PEM";
                }
                else if (fmt is not ("PEM" or "PFX"))
                {
                    throw new InputException("--private-key-format must be PEM or PFX, got " + fmt);
                }
                o.KeyFormat = fmt;
                o.Key = ReadFile(keyFile, "--update-private-key");
            }
            o.Csr = a.Has("--csr");
            o.Reset = a.Has("--reset-to-defaults");
            o.Apply = a.Has("--apply");
            // CancelChanges is implied by --create-self-signed / --delete-certificate without --apply
            o.Cancel = !o.Apply && (a.Has("--cancel") || o.SelfSigned || o.DeleteType != null);
            o.Diagnostics = a.Has("--transaction-diagnostics");
            return o;
        }

        private static string NodeIdArg(string s, string flag)
        {
            if (s.StartsWith("nsu=", StringComparison.Ordinal))
            {
                if (s.IndexOf(';', 4) < 0)
                {
                    throw new InputException(flag + ": malformed NodeId '" + s + "'");
                }
                return s;
            }
            try
            {
                NodeIds.Parse(s);
            }
            catch (InputException e)
            {
                throw new InputException(flag + ": " + e.Message);
            }
            return s;
        }

        private static ushort UInt16Arg(Args a, string flag, ushort def)
        {
            string v = a.Get(flag);
            if (v == null)
            {
                return def;
            }
            if (!ushort.TryParse(v, System.Globalization.NumberStyles.None, Inv.C, out ushort r))
            {
                throw new InputException(flag + " must be an integer 0..65535, got " + v);
            }
            return r;
        }

        private static byte[] ReadFile(string path, string flag)
        {
            try
            {
                return File.ReadAllBytes(path);
            }
            catch (Exception e)
            {
                throw new InputException(flag + " " + path + ": " + e.Message);
            }
        }

        /// <summary>A certificate file (PEM or DER) as DER.</summary>
        private static byte[] CertificateDer(string path, string flag)
        {
            ReadFile(path, flag);
            List<byte[]> certs;
            try
            {
                certs = Pki.ReadCertificates(path);
            }
            catch (Exception e)
            {
                throw new InputException(flag + " " + path + ": not a PEM or DER certificate: " + e.Message);
            }
            if (certs.Count == 0)
            {
                throw new InputException(flag + " " + path + ": no certificate");
            }
            return certs[0];
        }
    }

    /// <summary>
    /// client push (docs/CONTAINER_CONTRACT.md §1 "push flags", §4 push, §15): push certificate
    /// management as plain Call requests on the standard NodeIds of ServerConfiguration (Part 12
    /// §7.10) and on the FileType / TrustListType methods of the group's TrustList, all on the one
    /// session of the command (the transaction of Part 12 §7.10.2 is the session's).
    /// ServerPushConfigurationClient of Opc.Ua.Gds.Client 2.0.1 opens its own session and has no
    /// helper for the Part 12 1.05 methods (GetCertificates, CreateSelfSignedCertificate,
    /// DeleteCertificate, CancelChanges, ResetToServerDefaults), so it is not used.
    /// </summary>
    internal static class PushCommand
    {
        private const string Op = "push";
        private const int TrustListChunk = 4096;
        private const uint TrustListMasksAll = 15;

        private static readonly NodeId s_serverConfiguration = new(12637u);
        private static readonly NodeId s_updateCertificate = new(13737u);
        private static readonly NodeId s_createSigningRequest = new(12737u);
        private static readonly NodeId s_getRejectedList = new(12777u);
        private static readonly NodeId s_applyChanges = new(12740u);
        private static readonly NodeId s_getCertificates = new(32333u);
        private static readonly NodeId s_createSelfSigned = new(19342u);
        private static readonly NodeId s_deleteCertificate = new(19345u);
        private static readonly NodeId s_cancelChanges = new(25708u);
        private static readonly NodeId s_resetToServerDefaults = new(25709u);

        /// <summary>ServerConfiguration.TransactionDiagnostics (Part 12 §7.10.12): StartTime … Errors.</summary>
        private static readonly uint[] s_transactionDiagnostics = [32337, 32338, 32339, 32340, 32341, 32342];

        /// <summary>A Bad status of a step (its status key is already in the result).</summary>
        private sealed class StepFailed : Exception
        {
            public StepFailed(string step, uint code) : base(step + " returned a non-Good status")
            {
                Code = code;
            }

            public uint Code { get; }
        }

        private readonly record struct CallResult(StatusCode Status, ArrayOf<Variant> Outputs)
        {
            public object Out(int i) => Outputs.Count > i ? Outputs[i].AsBoxedObject(Variant.BoxingBehavior.Legacy) : null;
        }

        public static async Task<int> RunAsync(ClientContext c, PushOptions o)
        {
            await c.ConnectAsync().ConfigureAwait(false);
            NodeId groupId = c.Node(o.GroupId);
            NodeId typeId = c.Node(o.CertificateTypeId);
            NodeId? deleteType = o.DeleteType == null ? null : c.Node(o.DeleteType);
            var item = new JsonObject { ["certificateGroupId"] = Canonical.NodeId(groupId) };
            var r = new Result(Op);

            NodeId trustList;
            try
            {
                trustList = await ChildAsync(c, groupId, "TrustList").ConfigureAwait(false);
                item["trustList"] = TrustListJson(await ReadTrustListAsync(c, trustList).ConfigureAwait(false));
            }
            catch (StepFailed e)
            {
                r.Add(item).ServiceResult(e.Code).Error("service", "reading the TrustList of " + o.GroupId + ": " + e.Message).Print();
                return 4;
            }

            uint failed = 0;
            string failedStep = null;
            bool Step(string name, StatusCode status)
            {
                item[name + "Status"] = StatusNames.Json(status);
                if (StatusCode.IsGood(status))
                {
                    return true;
                }
                failed = status.Code;
                failedStep = name;
                return false;
            }

            var trusted = new Variant(!o.Issuer);
            bool ok = true;
            try
            {
                if (o.Add != null)
                {
                    NodeId m = await ChildAsync(c, trustList, "AddCertificate").ConfigureAwait(false);
                    ok = Step("addCertificate", (await CallAsync(c, trustList, m, new Variant(ByteString.From(o.Add)), trusted).ConfigureAwait(false)).Status);
                }
                if (ok && o.Remove != null)
                {
                    NodeId m = await ChildAsync(c, trustList, "RemoveCertificate").ConfigureAwait(false);
                    ok = Step("removeCertificate", (await CallAsync(c, trustList, m, new Variant(o.Remove), trusted).ConfigureAwait(false)).Status);
                }
                if (ok && o.GetCertificates)
                {
                    CallResult cr = await CallAsync(c, s_serverConfiguration, s_getCertificates, new Variant(groupId)).ConfigureAwait(false);
                    ok = Step("getCertificates", cr.Status);
                    if (ok)
                    {
                        item["certificateTypeIds"] = Json.Strings(NodeIds(cr.Out(0)).Select(Canonical.NodeId));
                        item["certificates"] = B64Array(cr.Out(1));
                    }
                }
                if (ok && o.SelfSigned)
                {
                    CallResult cr = await CallAsync(c, s_serverConfiguration, s_createSelfSigned,
                        new Variant(groupId), new Variant(typeId), new Variant(o.Subject),
                        new Variant(new ArrayOf<string>(o.Dns.ToArray())), new Variant(new ArrayOf<string>(o.Ip.ToArray())),
                        new Variant(o.LifetimeDays), new Variant(o.KeySize)).ConfigureAwait(false);
                    ok = Step("createSelfSignedCertificate", cr.Status);
                    if (ok)
                    {
                        item["selfSignedCertificate"] = B64(cr.Out(0));
                    }
                }
                if (ok && deleteType != null)
                {
                    ok = Step("deleteCertificate", (await CallAsync(c, s_serverConfiguration, s_deleteCertificate,
                        new Variant(groupId), new Variant(deleteType.Value)).ConfigureAwait(false)).Status);
                }
                if (ok && o.Update != null)
                {
                    // the go server rejects a null Variant for a ByteString / String argument: an
                    // absent key is an empty ByteString with PrivateKeyFormat ""
                    CallResult cr = await CallAsync(c, s_serverConfiguration, s_updateCertificate,
                        new Variant(groupId), new Variant(typeId), new Variant(ByteString.From(o.Update)),
                        new Variant(new ArrayOf<ByteString>(o.Issuers.Select(ByteString.From).ToArray())),
                        new Variant(o.KeyFormat ?? string.Empty),
                        new Variant(ByteString.From(o.Key ?? []))).ConfigureAwait(false);
                    ok = Step("updateCertificate", cr.Status);
                    if (ok)
                    {
                        item["applyChangesRequired"] = cr.Out(0) is bool b && b;
                    }
                }
                if (ok && o.Csr)
                {
                    CallResult cr = await CallAsync(c, s_serverConfiguration, s_createSigningRequest,
                        new Variant(groupId), new Variant(typeId), new Variant(string.Empty), new Variant(false),
                        new Variant(ByteString.From([]))).ConfigureAwait(false);
                    ok = Step("createSigningRequest", cr.Status);
                    if (ok)
                    {
                        item["certificateSigningRequest"] = B64(cr.Out(0));
                    }
                }
                if (ok)
                {
                    CallResult cr = await CallAsync(c, s_serverConfiguration, s_getRejectedList).ConfigureAwait(false);
                    ok = Step("getRejectedList", cr.Status);
                    if (ok)
                    {
                        item["rejectedCertificates"] = B64Array(cr.Out(0));
                    }
                }
                if (ok && o.Reset)
                {
                    ok = Step("resetToServerDefaults", (await CallAsync(c, s_serverConfiguration, s_resetToServerDefaults).ConfigureAwait(false)).Status);
                }
                bool applied = false;
                if (ok && o.Apply)
                {
                    ok = Step("applyChanges", (await CallAsync(c, s_serverConfiguration, s_applyChanges).ConfigureAwait(false)).Status);
                    applied = true;
                }
                if (ok && o.Cancel)
                {
                    ok = Step("cancelChanges", (await CallAsync(c, s_serverConfiguration, s_cancelChanges).ConfigureAwait(false)).Status);
                }
                // the diagnostics explain a failed ApplyChanges too: read them also then
                if (o.Diagnostics && (ok || applied))
                {
                    (StatusCode status, JsonObject d) = await ReadTransactionDiagnosticsAsync(c).ConfigureAwait(false);
                    item["transactionDiagnosticsStatus"] = StatusNames.Json(status);
                    if (d != null)
                    {
                        item["transactionDiagnostics"] = d;
                    }
                    if (ok && !StatusCode.IsGood(status))
                    {
                        failed = status.Code;
                        failedStep = "reading TransactionDiagnostics";
                        ok = false;
                    }
                }
                if (ok)
                {
                    item["trustListAfter"] = TrustListJson(await ReadTrustListAsync(c, trustList).ConfigureAwait(false));
                }
            }
            catch (StepFailed e)
            {
                failed = e.Code;
                failedStep = e.Message;
                ok = false;
            }
            r.Add(item);
            if (!ok)
            {
                r.ServiceResult(failed).Error("service", failedStep + " returned a non-Good status");
            }
            r.Print();
            return ok ? 0 : 4;
        }

        /// <summary>One Call: the CallMethodResult status (or the Bad service result) and outputs.</summary>
        private static async Task<CallResult> CallAsync(ClientContext c, NodeId obj, NodeId method, params Variant[] inputs)
        {
            try
            {
                CallResponse resp = await c.Session.CallAsync(c.Header(), new ArrayOf<CallMethodRequest>(new[]
                {
                    new CallMethodRequest { ObjectId = obj, MethodId = method, InputArguments = new ArrayOf<Variant>(inputs) }
                }), CancellationToken.None).ConfigureAwait(false);
                if (resp.Results.Count != 1)
                {
                    return new CallResult(StatusCodes.BadUnexpectedError, default);
                }
                CallMethodResult mr = resp.Results[0];
                return new CallResult(mr.StatusCode, mr.OutputArguments);
            }
            catch (ServiceResultException e) when (!ClientCommand.IsTransport(e.StatusCode.Code))
            {
                return new CallResult(e.StatusCode, default);
            }
        }

        /// <summary>The child of <paramref name="node"/> with BrowseName 0:<paramref name="name"/> (TranslateBrowsePaths).</summary>
        private static async Task<NodeId> ChildAsync(ClientContext c, NodeId node, string name)
        {
            StatusCode sc;
            try
            {
                var bp = new BrowsePath
                {
                    StartingNode = node,
                    RelativePath = new RelativePath
                    {
                        Elements = new ArrayOf<RelativePathElement>(new[]
                        {
                            new RelativePathElement
                            {
                                ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences,
                                IsInverse = false,
                                IncludeSubtypes = true,
                                TargetName = new QualifiedName(name, 0)
                            }
                        })
                    }
                };
                TranslateBrowsePathsToNodeIdsResponse resp = await c.Session.TranslateBrowsePathsToNodeIdsAsync(
                    c.Header(), new ArrayOf<BrowsePath>(new[] { bp }), CancellationToken.None).ConfigureAwait(false);
                BrowsePathResult br = resp.Results[0];
                sc = br.StatusCode;
                if (StatusCode.IsGood(sc) && br.Targets.Count > 0)
                {
                    ExpandedNodeId t = br.Targets[0].TargetId;
                    NodeId local = ExpandedNodeId.ToNodeId(t, c.Session.NamespaceUris);
                    if (!local.IsNull)
                    {
                        return local;
                    }
                    sc = StatusCodes.BadNodeIdUnknown;
                }
                else if (StatusCode.IsGood(sc))
                {
                    sc = StatusCodes.BadNoMatch;
                }
            }
            catch (ServiceResultException e) when (!ClientCommand.IsTransport(e.StatusCode.Code))
            {
                sc = e.StatusCode;
            }
            throw new StepFailed("TranslateBrowsePaths " + name, sc.Code);
        }

        /// <summary>Reads a TrustList object: OpenWithMasks(All), Read in chunks until an empty one, Close.</summary>
        private static async Task<TrustListDataType> ReadTrustListAsync(ClientContext c, NodeId trustList)
        {
            NodeId open = await ChildAsync(c, trustList, "OpenWithMasks").ConfigureAwait(false);
            CallResult r = await CallAsync(c, trustList, open, new Variant(TrustListMasksAll)).ConfigureAwait(false);
            if (!StatusCode.IsGood(r.Status))
            {
                throw new StepFailed("readTrustList", r.Status.Code);
            }
            if (r.Out(0) is not uint handle)
            {
                throw new StepFailed("readTrustList", StatusCodes.BadUnexpectedError.Code);
            }
            var data = new MemoryStream();
            try
            {
                NodeId read = await ChildAsync(c, trustList, "Read").ConfigureAwait(false);
                while (true)
                {
                    r = await CallAsync(c, trustList, read, new Variant(handle), new Variant(TrustListChunk)).ConfigureAwait(false);
                    if (!StatusCode.IsGood(r.Status))
                    {
                        throw new StepFailed("readTrustList", r.Status.Code);
                    }
                    byte[] chunk = Bytes(r.Out(0));
                    if (chunk == null || chunk.Length == 0)
                    {
                        break;
                    }
                    data.Write(chunk, 0, chunk.Length);
                }
            }
            finally
            {
                try
                {
                    NodeId close = await ChildAsync(c, trustList, "Close").ConfigureAwait(false);
                    await CallAsync(c, trustList, close, new Variant(handle)).ConfigureAwait(false);
                }
                catch (StepFailed)
                {
                    // best effort
                }
            }
            try
            {
                var tl = new TrustListDataType();
                using var d = new BinaryDecoder(data.ToArray(), Codec.Context);
                tl.Decode(d);
                return tl;
            }
            catch (Exception)
            {
                throw new StepFailed("readTrustList", StatusCodes.BadDecodingError.Code);
            }
        }

        /// <summary>The six TransactionDiagnostics variables in one Read: the status and the object (null if Bad).</summary>
        private static async Task<(StatusCode, JsonObject)> ReadTransactionDiagnosticsAsync(ClientContext c)
        {
            ArrayOf<DataValue> dvs;
            try
            {
                ReadResponse resp = await c.Session.ReadAsync(c.Header(), 0, TimestampsToReturn.Neither,
                    new ArrayOf<ReadValueId>(s_transactionDiagnostics.Select(i => new ReadValueId { NodeId = new NodeId(i), AttributeId = Attributes.Value }).ToArray()),
                    CancellationToken.None).ConfigureAwait(false);
                dvs = resp.Results;
            }
            catch (ServiceResultException e) when (!ClientCommand.IsTransport(e.StatusCode.Code))
            {
                return (e.StatusCode, null);
            }
            if (dvs.Count != s_transactionDiagnostics.Length)
            {
                return (StatusCodes.BadUnexpectedError, null);
            }
            var vals = new object[dvs.Count];
            for (int i = 0; i < dvs.Count; i++)
            {
                if (!StatusCode.IsGood(dvs[i].StatusCode))
                {
                    return (dvs[i].StatusCode, null);
                }
                vals[i] = dvs[i].WrappedValue.AsBoxedObject(Variant.BoxingBehavior.Legacy);
            }
            var errors = new JsonArray();
            foreach (object e in Elements(vals[5]))
            {
                errors.Add(TransactionError(e));
            }
            var d = new JsonObject
            {
                ["startTime"] = DateTimeJson(vals[0]),
                ["endTime"] = DateTimeJson(vals[1]),
                ["result"] = StatusNames.Json(vals[2] is StatusCode sc ? sc.Code : vals[2] is uint u ? u : 0),
                ["affectedTrustLists"] = Json.Strings(NodeIds(vals[3]).Select(Canonical.NodeId)),
                ["affectedCertificateGroups"] = Json.Strings(NodeIds(vals[4]).Select(Canonical.NodeId)),
                ["errors"] = errors
            };
            return (StatusCodes.Good, d);
        }

        /// <summary>One TransactionErrorType (TargetId, Error, Message), decoded from its binary body.</summary>
        private static JsonObject TransactionError(object e)
        {
            NodeId? target = null;
            uint? error = null;
            string message = null;
            if (e is ExtensionObject eo && !eo.IsNull)
            {
                byte[] body = eo.Body switch
                {
                    ByteString bs => bs.ToArray(),
                    byte[] raw => raw,
                    IEncodeable enc => Codec.EncodeBinaryBody(enc),
                    _ => null
                };
                if (body != null)
                {
                    try
                    {
                        using var d = new BinaryDecoder(body, Codec.Context);
                        target = d.ReadNodeId(null);
                        error = d.ReadStatusCode(null).Code;
                        LocalizedText lt = d.ReadLocalizedText(null);
                        message = lt.IsNullOrEmpty ? null : lt.Text;
                    }
                    catch (Exception)
                    {
                        // left undecoded
                    }
                }
            }
            return new JsonObject
            {
                ["targetId"] = target == null ? null : Canonical.NodeId(target.Value),
                ["error"] = StatusNames.Json(error ?? StatusCodes.BadDecodingError.Code),
                ["message"] = message
            };
        }

        private static JsonNode DateTimeJson(object v) => v switch
        {
            DateTimeUtc t when Canonical.HasTime(t) => JsonValue.Create(Canonical.Time(t)),
            DateTime dt when Canonical.HasTime(new DateTimeUtc(dt)) => JsonValue.Create(Canonical.Time(new DateTimeUtc(dt))),
            _ => null
        };

        private static IEnumerable<object> Elements(object v) => v is Array a && v is not byte[] ? a.Cast<object>() : v == null ? [] : [v];

        private static IEnumerable<NodeId> NodeIds(object v) => Elements(v).OfType<NodeId>();

        private static byte[] Bytes(object v) => v switch
        {
            byte[] b => b,
            ByteString bs => bs.IsNull ? null : bs.ToArray(),
            _ => null
        };

        private static JsonNode B64(object v)
        {
            byte[] b = Bytes(v);
            return b == null ? null : JsonValue.Create(Convert.ToBase64String(b));
        }

        private static JsonArray B64Array(object v)
        {
            if (v is byte[] single)
            {
                return Json.Strings([Convert.ToBase64String(single)]);
            }
            return Json.Strings(Elements(v).Select(Bytes).Where(b => b != null).Select(Convert.ToBase64String));
        }

        private static JsonArray B64(ArrayOf<ByteString> c) =>
            Json.Strings((c.ToArray() ?? []).Select(b => Convert.ToBase64String(b.Span)));

        private static JsonObject TrustListJson(TrustListDataType tl) => new()
        {
            ["specifiedLists"] = tl.SpecifiedLists,
            ["trustedCertificates"] = B64(tl.TrustedCertificates),
            ["trustedCrls"] = B64(tl.TrustedCrls),
            ["issuerCertificates"] = B64(tl.IssuerCertificates),
            ["issuerCrls"] = B64(tl.IssuerCrls)
        };
    }
}
