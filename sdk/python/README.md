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

Trust model: a cooperative contract, not a security boundary — the host
is fully trusted. See the repository's SECURITY.md.

Docs and spec: https://github.com/responsibleai/agent-control-spec
