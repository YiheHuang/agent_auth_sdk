# Security Policy

## Supported versions

| Version | Security fixes |
|---|---|
| `1.0.x` | Yes |
| `1.0.0rc1` | Until `1.0.0` is released |
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
- Verifiers use `registry_only` discovery and fail closed.
- Multi-process receivers use an atomic shared nonce store such as Redis.
- Reverse-proxied Agent endpoints configure their public base URL.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for trust boundaries and residual risks.
