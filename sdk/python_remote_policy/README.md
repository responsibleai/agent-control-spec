<!-- Copyright (c) Microsoft. All rights reserved. -->

# Remote policy polling for Agent Control Specification

`agent-control-spec-remote-policy` is the optional, pure-Python remote polling
distribution. Its import namespace is `agent_control_spec_remote_policy`.
The native `agent-control-spec` distribution remains the local policy evaluator:
installing it alone does not install HTTP, YAML, Azure, or polling code.

## Install

This checkout defines version **0.4.0b1**; the extraction is not a claim that
this distribution has been published. Until release, install from this checkout
or from locally built wheels:

```sh
python -m pip install ./sdk/python ./sdk/python_remote_policy
# Only when using the Azure adapter:
python -m pip install ./sdk/python "./sdk/python_remote_policy[azure]"
```

Run these commands from the repository root. Python 3.11 or later is required;
building the native dependency from source also requires its Rust build tools.
Once published, the corresponding distribution requirement is
`agent-control-spec-remote-policy==0.4.0b1` (or its `[azure]` extra).
The optional package requires `agent-control-spec>=0.4.0b1,<0.5`,
`httpx>=0.28.1,<0.29`, and `PyYAML>=6.0.3,<7`. The Azure extra adds
`azure-identity>=1.25.3,<2` and `aiohttp>=3.14.4,<4`.

## Use and ownership

The facade exports the common poller, configuration, source, error, and credential
types. Detailed artifact helpers are in `agent_control_spec_remote_policy.poller`.
For a host-owned configuration and explicit provider allow-list:

```python
from collections.abc import Mapping

from agent_control_spec_remote_policy import (
    CredentialProviderFactory,
    CredentialProviderRegistry,
    HttpPolicySource,
    PolicyPoller,
    PollerConfig,
)


async def serve(
    config: PollerConfig,
    factories: Mapping[str, CredentialProviderFactory],
) -> None:
    registry = CredentialProviderRegistry(factories)
    async with registry.open(config) as credentials:
        source = HttpPolicySource.from_config(config, credentials)
        async with PolicyPoller(config, source) as poller:
            for agent in config.agents:
                snapshot = poller.get_policy(agent.agent_id)
                # Feed the validated snapshot to the host's evaluator.
                # Fetching a policy is not an authorization to execute an action.
                assert snapshot.revision >= 1
```

`PollerConfig.from_yaml(...)` validates bounded, non-secret YAML configuration.
The host must choose trusted credential factories and policy API scope; downloaded
policy/configuration cannot expand the factory allow-list or supply credentials.
Keep actual secrets out of YAML, logs, and examples.

Keep the registry outside the source/poller context. The poller closes its source;
the source closes its HTTP client but **does not close credentials**. The registry
owns factory context entry/exit, including bounded cancellation and cleanup.
When supplying a credential directly, the host owns its lifetime. A directly
constructed `AzureAuthorizationProvider` also leaves the underlying async Azure
credential caller-owned. Do not suppress cleanup failures or treat a timeout as
proof that retained work stopped.

### Reusable credential interfaces

Both shapes are supported, with distinct purposes:

* `AuthorizationProvider.authorization() -> str` is an async **single-header**
  protocol: it supplies a validated `Authorization` value, such as a bearer token.
  `AzureAuthorizationProvider(AuthorizationProvider)` is the Azure implementation;
  its explicit scope, serialized refresh, bounded token cache, failure behavior,
  and cancellation semantics remain unchanged.
* `RequestAuthenticator.authenticate(AuthenticationRequest) -> Mapping[str, str]`
  is an async **request-aware** protocol for signing the final request.
  The immutable request view includes method, URL, headers, and body. The
  adapter validates returned add-only authentication headers and rejects
  reserved-field overwrites. This shape can support host-supplied AWS-style
  signers, but this package includes **no AWS signer** and makes no claim of
  verified AWS deployment.

`Credential` is the union accepted by the shared HTTP adapter and registry.
A credential implementing **both** protocols is ambiguous and rejected before
transport use. Custom providers use the same registry and source as Azure.
The tests exercise non-Azure single-header providers and deterministic HMAC
signing; the HMAC test double is not an AWS implementation.

`azure_credential_factories()` supplies the explicit `azure_cli` factory.
The facade and default registry do not import Azure SDKs until Azure credential
acquisition is needed. Azure SDKs are optional, not a fallback for custom providers.

## Migration from the unreleased in-tree feature

There are no compatibility shims or polling extras in the native SDK. Replace:

| Previous import | Standalone import |
| --- | --- |
| `agent_control_spec.remote_policy` | `agent_control_spec_remote_policy.poller` |
| `agent_control_spec.remote_policy_auth` | `agent_control_spec_remote_policy.auth` |
| `agent_control_spec.remote_policy_http` | `agent_control_spec_remote_policy.http` |
| `agent_control_spec.remote_policy_azure` | `agent_control_spec_remote_policy.azure` |

Replace native `[remote-policy]`/`[azure]` installation requirements with the new
distribution (and its `[azure]` extra when needed). Manifest parsing, manifest
version discovery, validation, and evaluation remain imports from
`agent_control_spec`, not from the optional package.

## Development and isolation checks

From the repository root, after installing the parent-managed development lock
and both packages into a development environment:

```sh
ruff format --check sdk/python_remote_policy
ruff check sdk/python_remote_policy
pyright --project sdk/python_remote_policy
pytest -c sdk/python_remote_policy/pyproject.toml sdk/python/tests sdk/python_remote_policy/tests
```

The strict type project covers production code, all moved tests, and the
parent-owned remote-policy examples. Test helpers and the JSON fixture stay in
`sdk/python_remote_policy/tests`; tests resolve the fixture beside their source,
so the optional package itself can be imported from an installed wheel. Tests
and examples require a checkout and are intentionally not shipped in the wheel.

Build separately, with an output directory outside either source tree:

```sh
python -m build --wheel --outdir dist/native sdk/python
python -m build --outdir dist/remote-policy sdk/python_remote_policy
```

The pure-Python build backend is pinned to `setuptools==84.0.0`. Inspect both
wheels and source archive with the packaging tests by setting `ACS_CORE_WHEEL`,
`ACS_REMOTE_POLICY_WHEEL`, and `ACS_REMOTE_POLICY_SDIST` to their exact paths, then running
`pytest -c sdk/python_remote_policy/pyproject.toml sdk/python_remote_policy/tests/test_packaging.py`.
Without those variables, archive checks are explicitly skipped; installed
metadata and checkout-boundary checks still run.

For full isolation, use two fresh environments: install only the native wheel in
one and confirm it has no remote/cloud requirements or `remote_policy*` modules;
install the native and optional wheels in the other, run `python -m pip check`,
import the facade without Azure installed, and run the checkout tests.
Add the Azure extra only for Azure-specific coverage. Do not interpret an
editable install or a shared development environment as proof of wheel isolation.
