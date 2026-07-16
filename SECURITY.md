# Security Policy

## Supported versions

| Version | Security fixes |
|---|---|
| `1.1.x` | Yes |
| `1.0.x` | Critical fixes until 2027-01-31 |
| `0.2.x` beta | Until 2026-10-31 |
| Earlier snapshots | No |

## Reporting

Please report vulnerabilities through the private
[GitHub Security Advisory](https://github.com/YiheHuang/agent_auth_sdk/security/advisories/new).
Include the affected version, deployment assumptions, reproduction steps and known mitigation. Do not open a
public issue before coordinated disclosure.

## Production baseline

- Registry runs as a non-root, single-worker service behind HTTPS.
- Every developer has an administrator-assigned, non-overlapping namespace.
- Production signers use Vault Transit or an equivalent non-exportable signer and a fixed key version.
- Verifiers only use the configured Registry and fail closed.
- Production receivers use a persistent local SQLite nonce database on a local filesystem.
- Each production process loads only the Vault tokens required by its own trust boundary.
- `local` mode is restricted to loopback and is not a substitute for production TLS.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for trust boundaries and residual risks.
