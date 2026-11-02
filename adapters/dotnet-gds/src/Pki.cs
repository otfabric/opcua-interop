// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// Bridges the test PKI (PEM files, docs/CONTAINER_CONTRACT.md §11 layout) and the stack's
    /// directory certificate stores (own / trusted / issuer / rejected with DER certificates).
    /// Adapted from dotnet/src/Pki.cs (RSA policies only).
    /// </summary>
    internal static class Pki
    {
        public static readonly (string Name, string Uri)[] Policies =
        [
            ("None", SecurityPolicies.None),
            ("Basic128Rsa15", SecurityPolicies.Basic128Rsa15),
            ("Basic256", SecurityPolicies.Basic256),
            ("Basic256Sha256", SecurityPolicies.Basic256Sha256),
            ("Aes128_Sha256_RsaOaep", SecurityPolicies.Aes128_Sha256_RsaOaep),
            ("Aes256_Sha256_RsaPss", SecurityPolicies.Aes256_Sha256_RsaPss)
        ];

        public static string PolicyUri(string name)
        {
            foreach ((string n, string u) in Policies)
            {
                if (n == name)
                {
                    return u;
                }
            }
            return null;
        }

        public static string PolicyName(string uri)
        {
            foreach ((string n, string u) in Policies)
            {
                if (u == uri)
                {
                    return n;
                }
            }
            return uri;
        }

        public static MessageSecurityMode Mode(string name) => name switch
        {
            "None" => MessageSecurityMode.None,
            "Sign" => MessageSecurityMode.Sign,
            "SignAndEncrypt" => MessageSecurityMode.SignAndEncrypt,
            _ => MessageSecurityMode.Invalid
        };

        /// <summary>DER bytes of every certificate in a PEM or DER file.</summary>
        public static List<byte[]> ReadCertificates(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            string text = Encoding.ASCII.GetString(raw);
            var result = new List<byte[]>();
            if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                int pos = 0;
                while ((pos = text.IndexOf("-----BEGIN CERTIFICATE-----", pos, StringComparison.Ordinal)) >= 0)
                {
                    int end = text.IndexOf("-----END CERTIFICATE-----", pos, StringComparison.Ordinal);
                    if (end < 0)
                    {
                        break;
                    }
                    string b64 = text.Substring(pos + 27, end - pos - 27);
                    result.Add(Convert.FromBase64String(new string(b64.Where(c => !char.IsWhiteSpace(c)).ToArray())));
                    pos = end + 25;
                }
                return result;
            }
            result.Add(raw);
            return result;
        }

        /// <summary>DER bytes of a PEM or DER CRL.</summary>
        public static byte[] ReadCrl(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            string text = Encoding.ASCII.GetString(raw);
            const string begin = "-----BEGIN X509 CRL-----";
            int pos = text.IndexOf(begin, StringComparison.Ordinal);
            if (pos < 0)
            {
                return raw;
            }
            int end = text.IndexOf("-----END X509 CRL-----", pos, StringComparison.Ordinal);
            string b64 = text.Substring(pos + begin.Length, end - pos - begin.Length);
            return Convert.FromBase64String(new string(b64.Where(c => !char.IsWhiteSpace(c)).ToArray()));
        }

        /// <summary>Loads an RSA certificate and its private key (PEM or DER; PKCS#8 / PKCS#1).</summary>
        public static X509Certificate2 LoadWithKey(string certPath, string keyPath)
        {
            byte[] der = ReadCertificates(certPath)[0];
            using X509Certificate2 pub = X509CertificateLoader.LoadCertificate(der);
            string keyText = File.ReadAllText(keyPath);
            if (pub.GetKeyAlgorithm() != "1.2.840.113549.1.1.1")
            {
                throw new NotSupportedException("only RSA application certificates are supported (" + certPath + ")");
            }
            using RSA rsa = RSA.Create();
            if (keyText.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(keyText);
            }
            else
            {
                rsa.ImportPkcs8PrivateKey(File.ReadAllBytes(keyPath), out _);
            }
            using X509Certificate2 withKey = pub.CopyWithPrivateKey(rsa);
            // round-trip through PKCS#12 so the key is persisted with the certificate
            byte[] pfx = withKey.Export(X509ContentType.Pkcs12);
            return X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.Exportable);
        }

        /// <summary>The URI SAN of a certificate (ApplicationUri), or null.</summary>
        public static string ApplicationUri(X509Certificate2 cert)
        {
            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "2.5.29.17")
                {
                    string uri = ParseUriSan(ext.RawData);
                    if (uri != null)
                    {
                        return uri;
                    }
                }
            }
            return null;
        }

        private static string ParseUriSan(byte[] raw)
        {
            try
            {
                var reader = new System.Formats.Asn1.AsnReader(raw, System.Formats.Asn1.AsnEncodingRules.DER);
                System.Formats.Asn1.AsnReader seq = reader.ReadSequence();
                while (seq.HasData)
                {
                    System.Formats.Asn1.Asn1Tag tag = seq.PeekTag();
                    if (tag.TagClass == System.Formats.Asn1.TagClass.ContextSpecific && tag.TagValue == 6)
                    {
                        return seq.ReadCharacterString(System.Formats.Asn1.UniversalTagNumber.IA5String, tag);
                    }
                    seq.ReadEncodedValue();
                }
            }
            catch (Exception)
            {
                // fall through
            }
            return null;
        }

        /// <summary>Writes a certificate (with private key) into an own store.</summary>
        public static void WriteOwn(string ownDir, string name, X509Certificate2 cert)
        {
            Directory.CreateDirectory(Path.Combine(ownDir, "certs"));
            Directory.CreateDirectory(Path.Combine(ownDir, "private"));
            File.WriteAllBytes(Path.Combine(ownDir, "certs", name + ".der"), cert.RawData);
            File.WriteAllBytes(Path.Combine(ownDir, "private", name + ".pfx"), cert.Export(X509ContentType.Pkcs12));
        }

        /// <summary>Copies certificates (any PEM/DER file) into a store's certs directory as DER.</summary>
        public static int CopyCertificates(string sourceDir, string targetStore)
        {
            Directory.CreateDirectory(Path.Combine(targetStore, "certs"));
            Directory.CreateDirectory(Path.Combine(targetStore, "crl"));
            int n = 0;
            if (!Directory.Exists(sourceDir))
            {
                return 0;
            }
            foreach (string f in Directory.GetFiles(sourceDir))
            {
                try
                {
                    int i = 0;
                    foreach (byte[] der in ReadCertificates(f))
                    {
                        File.WriteAllBytes(Path.Combine(targetStore, "certs", Path.GetFileNameWithoutExtension(f) + (i++ == 0 ? string.Empty : "-" + i) + ".der"), der);
                        n++;
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet-gds] warn: skipping certificate " + f + ": " + e.Message);
                }
            }
            return n;
        }

        public static void CopyCrls(string sourceDir, string targetStore)
        {
            Directory.CreateDirectory(Path.Combine(targetStore, "crl"));
            if (!Directory.Exists(sourceDir))
            {
                return;
            }
            foreach (string f in Directory.GetFiles(sourceDir))
            {
                try
                {
                    File.WriteAllBytes(Path.Combine(targetStore, "crl", Path.GetFileNameWithoutExtension(f) + ".crl"), ReadCrl(f));
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[dotnet-gds] warn: skipping CRL " + f + ": " + e.Message);
                }
            }
        }

        public static string TempDir(string prefix)
        {
            string dir = Path.Combine(Path.GetTempPath(), prefix + "-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>
    /// Approves the stack's certificate prompts (e.g. "domain not in certificate"): the test PKI
    /// names localhost / the adapter, not the container host name. Logged on stderr.
    /// </summary>
    internal sealed class AutoApproveDialog : Opc.Ua.Configuration.IApplicationMessageDlg
    {
        private string m_message;

        public override void Message(string text, bool ask)
        {
            m_message = text;
        }

        public override System.Threading.Tasks.Task<bool> ShowAsync()
        {
            Console.Error.WriteLine("[dotnet-gds] info: accepted: " + m_message);
            return System.Threading.Tasks.Task.FromResult(true);
        }
    }
}
