# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `opcua-interop`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/opcua-interop/security) tab → **Advisories** → **Report a vulnerability**), with a description, steps to reproduce and the affected image tag or digest.

Vulnerabilities in the bundled implementations themselves (open62541, Eclipse Milo) belong upstream; report them there, and tell us so that the pin can be moved.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No; pull the latest images |

## Security Considerations

### These are test fixtures, not products

The images run **OPC UA reference servers configured for testing, not for protection**, and clients that read, write, call methods and add or delete nodes on whatever endpoint they are given. That is their purpose.

- **Never attach a server to a plant, control or other production network**
- **Never point a client at a real server**: `write`, `call`, `node-management` and `register-server` change what they are sent to
- The baseline fixture advertises a `None`/`None` endpoint and accepts anonymous sessions. Username/password is also accepted on that endpoint, so the fixture credentials (`test-user` / `test-password`) cross the network in clear text
- `compose.yaml` and the `run-*` Makefile targets publish the servers on all host interfaces (ports 4840 and 4841). Run them on a host whose network you trust, or change the mapping to `127.0.0.1`

### Test PKI

- The repository contains no private keys. `certs/generate.sh` (or `make certs`) creates a test CA, server and client identities and an intentionally untrusted certificate in `certs/test-pki/`, which is git-ignored
- Everything under `certs/` is test material only: the certificates have long validity (10-year CA, 5-year leaf), and the `.pfx` bundles use the fixed password `password`. Never use them, or a CA that signed them, outside isolated test environments, and never add the test CA to a production trust list

### Image hardening

- The open62541 image runs as a non-root user (uid 10001). The Milo image runs as root
- Base images are pinned by tag, not by digest; Dependabot tracks them. open62541 is cloned from GitHub by release tag; Eclipse Milo comes from Maven Central at the version in `milo/pom.xml`
- Consumers should pin images by digest
