# Release checklist

1. Confirm both distribution names are available or owned on TestPyPI/PyPI.
2. Update both `pyproject.toml` versions and `CHANGELOG.md` together.
3. Run the Python 3.11–3.13 Linux/Windows CI matrix.
4. Build SDK and Registry sdist/wheel artifacts from a clean checkout.
5. Run `twine check --strict` and inspect archive contents; internal notes, runtime data and tests must be absent.
6. Configure the `testpypi` Trusted Publisher/environment and run the manual `Publish to TestPyPI` workflow; its clean-install job must pass.
7. Run CLI, Registry health, namespace, publish, verify, rotate and revoke smoke tests.
8. After TestPyPI approval, create a signed GitHub release; the protected `pypi` environment and OIDC Trusted Publishing workflow upload the exact CI artifacts.
