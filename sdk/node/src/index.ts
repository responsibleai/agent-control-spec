/**
 * Agent Control Specification — Node wrapper.
 *
 * ACS is a stateless policy decision runtime that plugs into
 * agent-hooks as an interceptor: a host registers {@link AcsInterceptor}
 * with its agent-hooks emitter; on every emission the engine runs the
 * manifest-bound evaluation pipeline (annotators → policy dispatcher →
 * normalization) and returns the resulting verdict. Every failure path
 * is fail-closed: a `deny` whose reason carries the engine's
 * `runtime_error:*` namespace.
 *
 * The interception contract — points, context, verdicts, host
 * obligations — is defined by AGENT-HOOKS-0.1 and consumed from
 * `@responsibleai/agent-hooks`; its types are re-exported here so a
 * host needs a single import.
 */
import type { AgentContext, Interceptor, Verdict } from "@responsibleai/agent-hooks";

// Generated loader for the native engine binding (napi).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const native = require("../binding.js") as {
  interceptorNew(manifestPath: string): unknown;
  intercept(handle: unknown, contextJson: string): string;
};

export type {
  AgentContext,
  Decision,
  Interceptor,
  Transform,
  Verdict,
  Warning,
} from "@responsibleai/agent-hooks";

export interface AcsInterceptorOptions {
  /** Payload-free identifier recorded on the record's `verdicts[].name`. */
  name?: string;
}

/** Wraps the ACS engine as an agent-hooks {@link Interceptor}. */
export class AcsInterceptor implements Interceptor {
  readonly name: string;
  private readonly handle: unknown;

  private constructor(handle: unknown, name: string) {
    this.handle = handle;
    this.name = name;
  }

  /**
   * Build an interceptor from a manifest path using the zero-config
   * dispatchers: bundled annotators; Rego policies through OPA, Cedar
   * through the built-in evaluator, `test` policies through their
   * embedded verdict. Custom policies require a host dispatcher and
   * fail closed under this construction.
   */
  static fromPath(manifestPath: string, options: AcsInterceptorOptions = {}): AcsInterceptor {
    return new AcsInterceptor(native.interceptorNew(manifestPath), options.name ?? "acs");
  }

  /**
   * Evaluate one agent context. Evaluation failures return a
   * fail-closed `deny` verdict (`runtime_error:*` reason); this method
   * throws only on boundary problems (non-object context).
   */
  intercept(context: AgentContext): Verdict {
    return JSON.parse(native.intercept(this.handle, JSON.stringify(context))) as Verdict;
  }
}
