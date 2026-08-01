# agent-control-spec (Python)

Python binding for the Agent Control Specification runtime: a stateless
policy decision engine that plugs into any
[agent-hooks](https://github.com/responsibleai/agent-hooks) host as an
interceptor.

```bash
pip install --pre agent-control-spec
```

```python
from agent_hooks import InterceptionEmitter, EnforcementMode
from agent_control_spec import AcsInterceptor

emitter = InterceptionEmitter(mode=EnforcementMode.ENFORCE)
emitter.register(AcsInterceptor("manifest.yaml"), "acs")
```

The manifest binds policies (Rego through OPA, Cedar through the
built-in evaluator, or `test` doubles) to interception points; the
runtime evaluates each context and returns an agent-hooks verdict.
Engine failures never raise into the host loop: they normalize into
fail-closed `deny` verdicts with `runtime_error:*` reasons.

Manifests can also be checked on their own, without building a runtime
or having `opa` on PATH. Useful when generating or migrating manifests:

```python
from agent_control_spec import ManifestInvalidError, validate_manifest

try:
    validate_manifest(source)
except ManifestInvalidError as error:
    print(error)  # names the offending field
```

A manifest that uses `extends` cannot be judged from its own source,
because validation checks references across the merged document. Pass a
path instead and the chain is resolved first:

```python
from agent_control_spec import validate_manifest_file

validate_manifest_file("manifest.yaml")
```

`supported_manifest_versions()` reports the grammar versions this
engine accepts. Read it rather than hardcoding the set.

Trust model: a cooperative contract, not a security boundary — the host
is fully trusted. See the repository's SECURITY.md.

Docs and spec: https://github.com/responsibleai/agent-control-spec
