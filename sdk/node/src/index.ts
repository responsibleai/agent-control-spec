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
import type {
  AgentContext,
  InterceptionPoint,
  Interceptor,
  Verdict,
} from "@responsibleai/agent-hooks";


// Generated loader for the native engine binding (napi).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const native = require("../binding.js") as {
  interceptorNew(manifestPath: string): unknown;
  intercept(handle: unknown, contextJson: string): string;
  policyActivate(manifestPath: string): unknown;
  policyActivateFromMemory(manifestYaml: string, bundlesJson: string): unknown;
  policyEvaluate(handle: unknown, point: string, contextJson: string): string;
  policyInterventionPoints(handle: unknown): string[];
  validateManifestFile(path: string): string | null;
  validateManifest(source: string): string | null;
  supportedManifestVersions(): string[];
};

export type {
  AgentContext,
  Decision,
  InterceptionPoint,
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

/**
 * One data document and where it mounts under `data`.
 *
 * On disk the mount point comes from the file's directory relative to
 * the bundle root. Nothing implies it in memory, so it is stated.
 */
export interface RegoDataDocument {
  /**
   * Path under `data`, outermost segment first. Omitted or empty mounts
   * at the data root.
   */
  mount?: readonly string[];
  document: unknown;
}

/** A Rego policy set the host holds in memory rather than on disk. */
export interface RegoBundle {
  /**
   * Module source keyed by name. The name is what a load failure
   * quotes, so name modules the way the host stores them rather than
   * inventing paths.
   */
  modules: Readonly<Record<string, string>>;
  data?: readonly RegoDataDocument[];
}

/**
 * One policy version, readied once and evaluated many times.
 *
 * {@link AcsInterceptor} answers "evaluate this agent context against a
 * manifest" and readies the policy lazily on the first call. This class
 * is the other split: {@link ActivatedPolicy.activate} pays for reading
 * the manifest, loading every Rego module and data document, and
 * compiling the entrypoint each intervention point queries; every later
 * {@link ActivatedPolicy.evaluate} costs no I/O and no compile.
   *
   * Compiling is bounded by the eval timeout: a policy too slow to
   * compile in that window activates anyway, not necessarily fully readied, and
   * pays compilation on its first evaluation instead.
 *
 * Activate once per policy version and keep the instance. A policy edit
 * on disk needs a new activation, which is the point: the host controls
 * when a version changes. The underlying handle is immutable and safe to
 * share across concurrent evaluations.
 */
export class ActivatedPolicy {
  private readonly handle: unknown;

  private constructor(handle: unknown) {
    this.handle = handle;
  }

  /**
   * Activate the manifest at `manifestPath` using the zero-config
   * dispatchers: bundled annotators; Rego policies in process, Cedar
   * through the built-in evaluator, `test` policies through their
   * embedded verdict.
   *
   * Throws when the manifest cannot be read, is rejected, or binds a
   * policy that readying finds broken (a missing bundle, say), and only
   * when readying finished: a bundle whose load does not complete
   * inside the deadline surfaces at the first evaluation instead. A
   * policy that merely needs real input to produce a verdict activates
   * fine.
   *
   * A manifest names its bundle relative to itself, so an absolute
   * manifest path is enough and the working directory does not matter.
   */
  static activate(manifestPath: string): ActivatedPolicy {
    return new ActivatedPolicy(native.policyActivate(manifestPath));
  }

  /**
   * Activate a manifest and its Rego, both supplied as values rather
   * than read from disk.
   *
   * `bundles` maps a policy id declared in `manifestYaml` to the modules
   * and data documents that policy evaluates, replacing whatever
   * `bundle` path the manifest names. A service that keeps manifests and
   * Rego in a database activates from them directly, instead of staging
   * a temporary directory per activation.
   *
   * Throws when the manifest is rejected, when a key of `bundles` names
   * a policy the manifest does not declare as Rego, and when a Rego
   * policy is left naming a relative `bundle` or data path. A manifest parsed
   * from a string has no directory of its own, so a relative path would
   * resolve against the working directory and read policy nobody chose.
   * An absolute path is left as written, so a manifest can mix policy
   * from the database with policy from a known location on disk.
   *
   * The activated policy is otherwise the same as one from
   * {@link ActivatedPolicy.activate}: evaluate it the same way, and
   * re-activate to change version.
   */
  static activateFromMemory(
    manifestYaml: string,
    bundles: Readonly<Record<string, RegoBundle>>,
  ): ActivatedPolicy {
    return new ActivatedPolicy(
      native.policyActivateFromMemory(manifestYaml, JSON.stringify(bundles)),
    );
  }

  /**
   * Evaluate one intervention point. This is the hot path.
   *
   * Evaluation failures return a fail-closed `deny` verdict
   * (`runtime_error:*` reason), including a point this policy version
   * does not bind. Throws only on boundary problems (unknown point
   * name, non-object context).
   */
  evaluate(point: InterceptionPoint, context: AgentContext): Verdict {
    return JSON.parse(
      native.policyEvaluate(this.handle, point, JSON.stringify(context)),
    ) as Verdict;
  }

  /**
   * The intervention points this policy version binds, in manifest
   * order. Use it to skip emitting points the policy does not govern.
   */
  interventionPoints(): readonly InterceptionPoint[] {
    return Object.freeze(
      native.policyInterventionPoints(this.handle) as InterceptionPoint[],
    );
  }

  /** Whether this policy version governs `point`. */
  governs(point: InterceptionPoint): boolean {
    return this.interventionPoints().includes(point);
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
