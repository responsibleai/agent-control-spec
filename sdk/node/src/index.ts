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
  validateManifestFile(path: string): string | null;
  validateManifest(source: string): string | null;
  supportedManifestVersions(): string[];
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
   * dispatchers: bundled annotators; Rego policies in process, Cedar
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

// A high surrogate not followed by a low one, or a low surrogate not
// preceded by a high one. `String.prototype.isWellFormed` would say this
// more directly but needs an ES2024 lib, and the package targets ES2022.
const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** A manifest failed grammar validation. */
export class ManifestInvalidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestInvalidError";
  }
}

/**
 * Validate manifest source against the grammar.
 *
 * Throws {@link ManifestInvalidError} when the manifest is rejected and
 * returns nothing when it is accepted. No runtime is built and nothing
 * is evaluated, so this works before a policy is runnable and without
 * a loadable policy bundle.
 */
export function validateManifest(source: string): void {
  if (typeof source !== "string") {
    throw new TypeError(`validateManifest expects a string, received ${typeof source}`);
  }
  // napi encodes a JS string as UTF-8 and silently substitutes U+FFFD
  // for an unpaired surrogate, which would have the engine judge a
  // document the caller never supplied and report on text they never
  // wrote. Invalid encoding is an explicit error here, never a lossy
  // conversion. Matches the Python and .NET bindings.
  if (UNPAIRED_SURROGATE.test(source)) {
    throw new TypeError("validateManifest received a string with an unpaired surrogate");
  }
  // The native call returns the engine's message for a rejected
  // manifest and throws only when the call itself fails, so a boundary
  // failure propagates as itself rather than being relabelled.
  const rejection = native.validateManifest(source);
  if (rejection !== null && rejection !== undefined) {
    throw new ManifestInvalidError(rejection);
  }
}

/**
 * Validate a manifest file, resolving `extends` first.
 *
 * Use this for a manifest that inherits. It reads from disk and may
 * fetch URL `extends`, exactly as loading a runtime would.
 */
export function validateManifestFile(path: string): void {
  if (typeof path !== "string") {
    throw new TypeError(`validateManifestFile expects a string, received ${typeof path}`);
  }
  const rejection = native.validateManifestFile(path);
  if (rejection !== null && rejection !== undefined) {
    throw new ManifestInvalidError(rejection);
  }
}

/**
 * The manifest grammar versions this engine accepts. Read it rather
 * than hardcoding the set; it moves with the engine.
 */
export function supportedManifestVersions(): readonly string[] {
  return Object.freeze(native.supportedManifestVersions());
}
