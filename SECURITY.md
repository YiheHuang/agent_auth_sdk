# Security Policy

## Supported versions

`0.1.x` beta receives security fixes. Earlier internal beta snapshots are unsupported and must not be deployed publicly.

## Reporting

Please report vulnerabilities through the repository's private [GitHub Security Advisory](https://github.com/YiheHuang/agent_auth_sdk/security/advisories/new). Include the affected version, deployment assumptions, reproduction steps and any known mitigation. Do not open a public issue before coordinated disclosure.

## Deployment baseline

- Registry must use the provided single-worker SQLite mode behind HTTPS.
- Every developer must have an administrator-assigned namespace.
- Production signers must use Vault Transit or an equivalent non-exportable signer.
- Verifiers configured with a Registry should retain the default fail-closed discovery policy.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the complete trust model.
