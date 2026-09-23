# Add ACS policy checks to a tool call with Agent Hooks

Put the hook where your application dispatches a tool, immediately before
the tool executes. ACS evaluates each policy. Agent Hooks combines the
verdicts. Your application either stops the call or executes it with the
permitted arguments.

This guide wraps a refund operation with two policies: one caps the amount,
and the other checks which orders may receive it. Follow the
[SDK README](../sdk/python/README.md) to install the packages. The Python
blocks below form one program; run them in order from the repository root.

## 1. Identify the operation to guard

Start with the function your application already calls. Here it writes to
an in-memory ledger so you can see what executed without making a payment:

```python
ledger = []


def issue_refund(ledger, *, order_id, amount):
    ledger.append({"order_id": order_id, "amount": amount})
```

Route every call to this function through the guard in step 4. In an agent,
that usually means changing the shared tool dispatcher, not just the code
that asks the model to choose a tool. A `pre_tool_call` check can prevent
the effect; a `post_tool_call` check can only govern the result after it
happens.

If your framework already emits Agent Hooks contexts, register the policies
with its emitter instead of creating a second interception path. Otherwise,
build the context at your application's dispatch boundary as shown next.

## 2. Map application data to the policy input

Create an `AgentContextBuilder` for the session and use the method for the
boundary you are guarding:

```python
from agent_hooks import AgentContextBuilder

builder = AgentContextBuilder(
    agent_id="refund-assistant", framework="example", session_id="session-1"
)


def refund_context(call_id, order_id, amount):
    return builder.pre_tool_call(
        call_id=call_id,
        name="issue_refund",
        args={"order_id": order_id, "amount": amount},
    )
```

In your application, supply its agent and session identifiers and the
actual invocation's ID, tool name, and arguments. The builder supplies
the envelope, sequence, and timestamp. It places the arguments in
`tool_call.args` and exposes them as the hook's `target`.

The [limits manifest](../examples/python_composition/limits.yaml) and
[orders manifest](../examples/python_composition/orders.yaml) both select
`$.tool_call.args` as `policy_target` and `$.tool_call.name` as
`tool_name_from`. Their Rego rules therefore read the amount at
`input.policy_target.value.amount`. When adapting the example, keep the
context shape, manifest paths, tool catalog, and policy field names aligned.

Both manifests bind `pre_tool_call` only, so send only that point to this
emitter. For other points, use dedicated emitters containing the controls
that bind them, or extend every manifest to cover all points a shared
emitter receives. An unbound point is a denial, not an implicit pass.
Returning allow from a scope wrapper would attribute a decision to a
policy that never evaluated the context; alone at a point, it is a permit.

## 3. Register the policies in the order they should run

Construct the controls at startup and reuse the emitter for this session:

```python
from pathlib import Path
from agent_control_spec import AcsInterceptor
from agent_hooks import CompositionConfig, EnforcementMode, InterceptionEmitter

policies = Path("examples/python_composition")
emitter = InterceptionEmitter(
    mode=EnforcementMode.ENFORCE,
    composition=CompositionConfig.run_all(),
)
emitter.register(AcsInterceptor(str(policies / "limits.yaml")), "limits")
emitter.register(AcsInterceptor(str(policies / "orders.yaml")), "orders")
emitter.set_max_records(100)
```

The emitter retains records even when it returns them to the caller.
This bound prevents unbounded growth; step 5 drains the buffer after
each handled call. For durable audit, connect `set_record_sink` to your
application's audit transport. A bounded buffer or console output is not
durable storage.

The limits policy rejects invalid amounts and caps positive amounts at 100.
The orders policy permits `A-1001` and `A-1003` only for a positive amount
no greater than 100.

Choose `sequential/run_all` here because the order check should see the
amount **after** the cap. Agent Hooks runs `limits`, applies its transform
to the context, then calls `orders` with the updated arguments. An ordinary
deny does not stop evaluation of the remaining controls, but it blocks the
operation. A transform that cannot be applied stops the fold with a denial.

If your controls should judge the original request independently, use
`parallel/strictest` instead. In this example that would deny a request for
150: the order check would see 150, not the proposed cap of 100.

`AcsInterceptor` runs synchronously. Before using this path with blocking
policies in an async service, follow the
[SDK's async guidance](../sdk/python/README.md#activating-a-policy-version).
Awaiting the emitter does not make synchronous policy evaluation nonblocking.

## 4. Execute only after the combined decision permits it

Replace the direct tool invocation with a guarded call:

```python
from agent_hooks import InterceptionBlocked


async def guarded_refund(call_id, order_id, amount):
    context = refund_context(call_id, order_id, amount)
    try:
        outcome = await emitter.emit(context)
    except InterceptionBlocked as blocked:
        return blocked.result

    issue_refund(ledger, **outcome.target)
    return outcome.record
```

On denial, the application returns before calling `issue_refund`. On
permission, it passes `outcome.target`, which contains any applied
transformation. Passing the original `amount` would bypass the cap.
In your application, handle the blocked result as a refused tool call,
not as a reason to retry without the hook.
Other exceptions from `emit()` also prevent execution and may produce no
record. Let your dispatcher report those errors; it must not retry the
operation without the hook.

Keep `ENFORCE` for this path. `EVALUATE_ONLY` records decisions without
blocking calls or applying transforms. Evaluation errors fail closed;
do not catch them and run the operation anyway.

The orders policy is the last control here and never transforms arguments.
If you add a later transform, recheck any required constraints it can
invalidate before executing the operation.

## 5. Check the decision and the arguments actually used

Run one allowed request, one denied request, and one transformed request:

```python
import asyncio


async def run():
    for call_id, order_id, amount in (
        ("allow", "A-1001", 40),
        ("deny", "blocked-order", 40),
        ("transform", "A-1003", 150),
    ):
        record = await guarded_refund(call_id, order_id, amount)
        print(call_id, record.verdict.decision.value, record.proceeds)
        print([(v.name, v.decision.value) for v in record.verdicts])
        emitter.take_records()

    assert ledger == [
        {"order_id": "A-1001", "amount": 40},
        {"order_id": "A-1003", "amount": 100},
    ]
    print(ledger)


asyncio.run(run())
```

The first request produces two allows. The second is denied by `orders`
and never reaches the ledger. The third produces a transform from `limits`
and an allow from `orders`; the operation receives 100 rather than 150.

`record.verdict` is the combined decision. `record.verdicts` identifies the
contributing controls and their decisions. Check both, but also test the
operation itself: a denial must mean zero invocations, and a transform must
change the arguments received. `take_records()` drains the retained copies
after this example handles the returned record. The
[example and tests](../examples/python_composition/README.md) exercise these
conditions using the published packages.

## If your policies require approval

Neither policy above requests approval. If you add a liftable deny, register
a resolver only for decisions the application allows a reviewer to override.
Without a resolver, that deny still blocks. With `run_all`, an ordinary deny
from another control takes precedence and prevents approval from allowing
the operation.

Do not assume approval continues through later controls. The default
`first_deny` profile uses `on_approval: stop`, which can skip them after an
approval. `OnApproval.RESUME` continues that fold, but a standing deny still
stops dispatch. Keep the profile explicit, and revalidate required constraints
if an approval resolver changes the final arguments.
