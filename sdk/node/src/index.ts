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
  interceptorNewWithHooks(
    manifestPath: string,
    annotatorDispatcher?:
      | ((name: string, invocationJson: string, policyInputJson: string) => string)
      | null,
    policyDispatcher?: ((invocationJson: string) => string) | null,
    telemetrySink?: ((eventJson: string) => void) | null,
    perfTelemetry?: string | null,
    limitsJson?: string | null,
  ): unknown;
  intercept(handle: unknown, contextJson: string): string;
  defaultLimits(): string;
  policyActivate(manifestPath: string): unknown;
  policyActivateFromMemory(manifestYaml: string, bundlesJson: string): unknown;
  policyActivateWithHooks(
    manifestPath: string,
    annotatorDispatcher?:
      | ((name: string, invocationJson: string, policyInputJson: string) => string)
      | null,
    policyDispatcher?: ((invocationJson: string) => string) | null,
  ): unknown;
  policyActivateFromMemoryWithHooks(
    manifestYaml: string,
    bundlesJson: string,
    annotatorDispatcher?:
      | ((name: string, invocationJson: string, policyInputJson: string) => string)
      | null,
    policyDispatcher?: ((invocationJson: string) => string) | null,
  ): unknown;
  policyEvaluate(handle: unknown, point: string, contextJson: string): string;
  policyInterventionPoints(handle: unknown): string[];
  validateManifestFile(path: string): string | null;
  validateManifest(source: string): string | null;
  validateManifestDetailed(source: string): string;
  validateArtifactsDetailed(manifestYaml: string, bundlesJson: string): string;
  parseManifest(source: string): string;
  mergeManifests(sourcesJson: string): string;
  supportedManifestVersions(): string[];
  streamSessionNew(configJson: string): unknown;
  streamSessionObserve(handle: unknown, sourceType: string, runes: number): number;
  streamSessionObserveText(handle: unknown, sourceType: string, text: string): number;
  streamSessionRecordOutcome(
    handle: unknown,
    task: string,
    sourceType: string,
    start: number,
    end: number,
    outcome: string,
  ): void;
  streamSessionRecordVerdict(
    handle: unknown,
    task: string,
    sourceType: string,
    start: number,
    end: number,
    verdictJson: string,
  ): void;
  streamSessionAdvance(handle: unknown, track: string): number | null;
  streamSessionSafeOffset(handle: unknown, track: string): number | null;
  streamSessionPending(handle: unknown, track: string): number;
  streamSessionWatermark(handle: unknown, track: string): string;
  streamSessionState(handle: unknown): string;
  streamSessionEndOfPayloads(handle: unknown): void;
  streamSessionFinish(handle: unknown): string;
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

// ---------------------------------------------------------------------
// Host extension surface: annotator dispatcher, policy dispatcher,
// telemetry sink, perf telemetry level. The zero-config path stays
// unchanged; a host that supplies any of these hooks gets the same
// engine construction the Rust and .NET/FFI SDKs already expose.
//
// The dispatcher callbacks are called SYNCHRONOUSLY on the JS thread
// from inside the engine's evaluation, which is legal here because the
// engine call itself is driven by a napi function running on the JS
// thread. A dispatcher that throws surfaces as a fail-closed
// `runtime_error:*` deny; the engine never treats a thrown callback as
// "no annotation".
// ---------------------------------------------------------------------

/**
 * A JSON-compatible value the boundary carries verbatim.
 *
 * Named separately from `unknown` so a dispatcher signature can say what
 * kind of thing it reads and returns without opening the door to values
 * (functions, symbols, class instances) the engine cannot round-trip.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/**
 * Fields the engine hands to a host annotator: `type` (`classifier`,
 * `llm`, `endpoint`), `from` (JSONPath expression), and every extra
 * key the manifest attached to the annotator or the annotation.
 */
export interface AnnotatorInvocation {
  readonly type: "classifier" | "llm" | "endpoint";
  readonly from: string;
  readonly [key: string]: JsonValue;
}

/**
 * Fields the engine hands to a host policy dispatcher. A serialized
 * `PreparedPolicyInvocation` — carrying `policy_id`, `policy_type`,
 * `intervention_point`, `input`, and the policy-specific configuration
 * — routed to whichever engine the host runs. The precise shape moves
 * with the engine; treat it as opaque JSON and let the engine describe
 * what to key off.
 */
export interface PolicyInvocation {
  readonly policy_id: string;
  readonly policy_type: string;
  readonly intervention_point: string;
  readonly input: JsonValue;
  readonly [key: string]: JsonValue;
}

/**
 * One telemetry event the engine emits. Every field maps 1:1 with the
 * `TelemetryEvent` the FFI binding surfaces and the Rust engine
 * declares, so a sink written for another SDK reads the same shape here.
 */
export interface TelemetryEvent {
  readonly event_type: string;
  readonly intervention_point: string;
  readonly decision: string | null;
  readonly reason_code: string | null;
  readonly error_class: string | null;
  readonly policy_id: string | null;
  readonly annotators: readonly string[];
  readonly enforcement_mode: string | null;
  readonly duration_ms: number | null;
  readonly evidence_artefact: string | null;
  readonly evidence_verification_pointer_keys: readonly string[];
  readonly action_identity: string | null;
  readonly metadata: Readonly<Record<string, string>>;
}

/**
 * A host annotator dispatcher.
 *
 * Called synchronously from inside `intercept`/`evaluate`; return a
 * value the manifest's `preliminary_policy_input` merge shape expects
 * (typically a JSON object per the annotator's contract). Throwing
 * fails the surrounding evaluation closed with a
 * `runtime_error:annotation_failed` deny.
 */
export type AnnotatorDispatcher = (
  name: string,
  invocation: AnnotatorInvocation,
  preliminaryPolicyInput: JsonValue,
) => JsonValue;

/**
 * A host policy dispatcher.
 *
 * Called synchronously; return the policy output as JSON per the
 * engine's expected shape (a `decision` string plus any extras). A
 * throw fails the evaluation closed with a
 * `runtime_error:policy_invocation_failed` deny.
 */
export type PolicyDispatcher = (invocation: PolicyInvocation) => JsonValue;

/**
 * A telemetry sink.
 *
 * Called synchronously with each event the engine emits at the
 * configured perf level. A sink cannot fail an evaluation; a throw
 * from the sink is swallowed to preserve that guarantee.
 */
export type TelemetrySink = (event: TelemetryEvent) => void;

/**
 * How much per-evaluation timing to emit.
 *
 * - `off` (default): only the final decision event.
 * - `external`: adds boundary events (annotator dispatch, policy
 *   evaluation).
 * - `full`: adds stage timing events for a full performance profile.
 */
export type PerfTelemetry = "off" | "external" | "full";

/**
 * Resource caps overriding the engine's defaults, field by field.
 *
 * `Limits` is a denial-of-service control surface: a host feeding
 * large payloads raises `maxSnapshotBytes`; one hardening against a
 * hostile manifest lowers `maxExtendsDepth` or
 * `manifestUrlTimeoutMs`. Each field is individually optional; an
 * absent field keeps its own default, so a host raising one cap does
 * not restate the other nine. A field present but not a non-negative
 * integer is a hard error, not a silently-kept default: a host that
 * asked for a smaller bound and got the larger one would believe it
 * was protected when it was not.
 *
 * See {@link DEFAULT_LIMITS} for the shipped values.
 */
export interface Limits {
  /** Cap on the canonicalized context snapshot in bytes. */
  max_snapshot_bytes?: number;
  /** JSON nesting depth accepted anywhere in policy input/output. */
  max_policy_input_depth?: number;
  /** Number of annotators the engine will dispatch per intervention point. */
  max_annotators_per_point?: number;
  /** Per-annotator serialized output cap in bytes. */
  max_annotator_output_bytes?: number;
  /** Policy-decision serialized output cap in bytes. */
  max_policy_output_bytes?: number;
  /** Manifest `extends` chain length. */
  max_extends_depth?: number;
  /** Composed manifest total size cap in bytes. */
  max_merged_manifest_bytes?: number;
  /** Per-URL manifest fetch body cap in bytes. */
  max_manifest_url_bytes?: number;
  /** Per-URL manifest fetch deadline in milliseconds. */
  manifest_url_timeout_ms?: number;
  /** Per-URL manifest fetch redirect count. */
  max_manifest_url_redirects?: number;
}

/**
 * The engine's shipped resource caps, as a frozen object. Read this to
 * see what a `limits` mapping is overriding; a shipping change to
 * another default cannot then be silently absorbed by a stale mapping.
 */
export const DEFAULT_LIMITS: Readonly<Required<Limits>> = Object.freeze(
  JSON.parse(native.defaultLimits()) as Required<Limits>,
);

/**
 * Host extension points. Each is optional; supplying one replaces the
 * zero-config default for that slot.
 */
export interface HostHooks {
  annotatorDispatcher?: AnnotatorDispatcher;
  policyDispatcher?: PolicyDispatcher;
  telemetrySink?: TelemetrySink;
  perfTelemetry?: PerfTelemetry;
  /**
   * Resource caps overriding the engine's defaults, field by field.
   * See {@link Limits} and {@link DEFAULT_LIMITS}.
   */
  limits?: Readonly<Limits>;
}

// --- Bridges between the object-oriented TS surface and the JSON --------
// string wire the native binding uses. Keeping the parse/serialize step
// here means the native dispatcher signatures stay simple `String →
// String` and every host callback sees objects, not text.

function wrapAnnotatorDispatcher(
  dispatcher: AnnotatorDispatcher,
): (name: string, invocationJson: string, policyInputJson: string) => string {
  return (name, invocationJson, policyInputJson) => {
    // A parse or a throwing dispatcher must propagate as a JS exception:
    // the native binding turns that into a fail-closed
    // `runtime_error:annotation_failed` deny. Never swallow — a
    // silently caught error would read as "annotation succeeded with
    // undefined".
    const invocation = JSON.parse(invocationJson) as AnnotatorInvocation;
    const policyInput = JSON.parse(policyInputJson) as JsonValue;
    const result = dispatcher(name, invocation, policyInput);
    return JSON.stringify(result ?? null);
  };
}

function wrapPolicyDispatcher(
  dispatcher: PolicyDispatcher,
): (invocationJson: string) => string {
  return (invocationJson) => {
    const invocation = JSON.parse(invocationJson) as PolicyInvocation;
    const result = dispatcher(invocation);
    return JSON.stringify(result ?? null);
  };
}

function wrapTelemetrySink(sink: TelemetrySink): (eventJson: string) => void {
  return (eventJson) => {
    // A sink cannot fail an evaluation, so wrap in try/catch and drop
    // the throw. Matches the engine contract.
    try {
      const event = JSON.parse(eventJson) as TelemetryEvent;
      sink(event);
    } catch {
      // intentionally swallowed
    }
  };
}

function hasHostHooks(options: HostHooks): boolean {
  return (
    options.annotatorDispatcher !== undefined ||
    options.policyDispatcher !== undefined ||
    options.telemetrySink !== undefined ||
    options.perfTelemetry !== undefined ||
    options.limits !== undefined
  );
}

export interface AcsInterceptorOptions extends HostHooks {
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
   * Build an interceptor from a manifest path.
   *
   * With no `options`, uses the zero-config dispatchers: bundled
   * annotators; Rego policies in process, Cedar through the built-in
   * evaluator, `test` policies through their embedded verdict. Custom
   * policies require a host dispatcher and fail closed under this
   * construction.
   *
   * Supply `annotatorDispatcher`, `policyDispatcher`, `telemetrySink`,
   * `perfTelemetry`, or `limits` to override the engine's extension
   * points and resource caps. Each callback is called synchronously on
   * the JS thread from inside `intercept`. A callback that throws
   * surfaces as a fail-closed `runtime_error:*` deny rather than
   * reading as "no annotation". A `limits` mapping overrides only the
   * fields it names; the rest keep the engine's defaults, see
   * {@link DEFAULT_LIMITS}.
   */
  static fromPath(manifestPath: string, options: AcsInterceptorOptions = {}): AcsInterceptor {
    const name = options.name ?? "acs";
    const handle = hasHostHooks(options)
      ? native.interceptorNewWithHooks(
          manifestPath,
          options.annotatorDispatcher
            ? wrapAnnotatorDispatcher(options.annotatorDispatcher)
            : null,
          options.policyDispatcher
            ? wrapPolicyDispatcher(options.policyDispatcher)
            : null,
          options.telemetrySink ? wrapTelemetrySink(options.telemetrySink) : null,
          options.perfTelemetry ?? null,
          options.limits ? JSON.stringify(options.limits) : null,
        )
      : native.interceptorNew(manifestPath);
    return new AcsInterceptor(handle, name);
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
 * Host extension points for {@link ActivatedPolicy}.
 *
 * Activation uses the engine's `activate_with` surface, which takes
 * only the annotator and policy dispatchers; telemetry and perf level
 * are configured on the interceptor path (see {@link AcsInterceptor})
 * because activation records no per-evaluation events itself.
 */
export interface ActivatedPolicyOptions {
  annotatorDispatcher?: AnnotatorDispatcher;
  policyDispatcher?: PolicyDispatcher;
}

function hasActivationHooks(options: ActivatedPolicyOptions): boolean {
  return (
    options.annotatorDispatcher !== undefined || options.policyDispatcher !== undefined
  );
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
   *
   * Supply `annotatorDispatcher` or `policyDispatcher` in `options` to
   * override the engine's extension points; each callback is called
   * synchronously on the JS thread from inside `evaluate` and fails
   * closed on throw.
   */
  static activate(
    manifestPath: string,
    options: ActivatedPolicyOptions = {},
  ): ActivatedPolicy {
    const handle = hasActivationHooks(options)
      ? native.policyActivateWithHooks(
          manifestPath,
          options.annotatorDispatcher
            ? wrapAnnotatorDispatcher(options.annotatorDispatcher)
            : null,
          options.policyDispatcher
            ? wrapPolicyDispatcher(options.policyDispatcher)
            : null,
        )
      : native.policyActivate(manifestPath);
    return new ActivatedPolicy(handle);
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
    options: ActivatedPolicyOptions = {},
  ): ActivatedPolicy {
    const handle = hasActivationHooks(options)
      ? native.policyActivateFromMemoryWithHooks(
          manifestYaml,
          JSON.stringify(bundles),
          options.annotatorDispatcher
            ? wrapAnnotatorDispatcher(options.annotatorDispatcher)
            : null,
          options.policyDispatcher
            ? wrapPolicyDispatcher(options.policyDispatcher)
            : null,
        )
      : native.policyActivateFromMemory(manifestYaml, JSON.stringify(bundles));
    return new ActivatedPolicy(handle);
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

// ---------------------------------------------------------------------
// Manifest tooling: parse, chain-compose, and structured diagnostics.
//
// The engine ships these APIs on `Manifest`; the wrapper exposes them
// here so authoring, migration, and CI tools can drive parse, overlay
// composition, and per-field validation from Node without staging a
// manifest to disk first.
// ---------------------------------------------------------------------

/**
 * A structured description of a manifest that did not pass validation.
 *
 * `code` is the reserved `runtime_error:*` reason a diagnostic-consuming
 * tool keys off; `message` is the engine's human-readable detail;
 * `severity` is always `"error"`; `field` is a best-effort pointer to
 * the offending manifest field (a YAML key or an engine-declared
 * identifier) so an editor can render the problem inline. `field` is
 * `null` when the message does not identify one.
 */
export interface ManifestDiagnostic {
  readonly code: string;
  readonly message: string;
  readonly severity: "error";
  readonly field: string | null;
}

/**
 * Parse manifest YAML into an object without validating references.
 *
 * The document is deserialized as-written: a manifest with an
 * unresolved `extends` chain returns fine. Use {@link validateManifest}
 * or {@link validateManifestDetailed} to judge whether the fragment is
 * runnable.
 *
 * Throws when the YAML does not parse.
 */
export function parseManifest(source: string): Record<string, unknown> {
  if (typeof source !== "string") {
    throw new TypeError(`parseManifest expects a string, received ${typeof source}`);
  }
  if (UNPAIRED_SURROGATE.test(source)) {
    throw new TypeError("parseManifest received a string with an unpaired surrogate");
  }
  return JSON.parse(native.parseManifest(source)) as Record<string, unknown>;
}

/**
 * Compose a chain of manifest YAML documents into one merged manifest.
 *
 * `sources` is ordered outermost base first, deltas after. This is the
 * overlay case, resolved the same way the engine resolves `extends`
 * when it walks a manifest tree. The returned object is the merged
 * manifest as JSON.
 *
 * Throws when a source does not parse, when the merged result is
 * invalid, or when `sources` is empty.
 */
export function mergeManifests(sources: readonly string[]): Record<string, unknown> {
  if (!Array.isArray(sources)) {
    throw new TypeError("mergeManifests expects an array of manifest sources");
  }
  for (const source of sources) {
    if (typeof source !== "string") {
      throw new TypeError("mergeManifests received a non-string source");
    }
    if (UNPAIRED_SURROGATE.test(source)) {
      throw new TypeError(
        "mergeManifests received a source with an unpaired surrogate",
      );
    }
  }
  return JSON.parse(native.mergeManifests(JSON.stringify(sources))) as Record<
    string,
    unknown
  >;
}

/**
 * Validate manifest source and return structured findings.
 *
 * An empty array means the manifest passed validation. Each finding
 * carries an engine reason code, the detail message, and where
 * possible the offending field name so an editor can render the
 * problem inline. Use this instead of {@link validateManifest} when
 * you need to render results, not just yes/no.
 *
 * Throws only on boundary problems (non-string input, unpaired
 * surrogate); an invalid manifest returns a non-empty array.
 */
export function validateManifestDetailed(source: string): readonly ManifestDiagnostic[] {
  if (typeof source !== "string") {
    throw new TypeError(
      `validateManifestDetailed expects a string, received ${typeof source}`,
    );
  }
  if (UNPAIRED_SURROGATE.test(source)) {
    throw new TypeError(
      "validateManifestDetailed received a string with an unpaired surrogate",
    );
  }
  return Object.freeze(
    JSON.parse(native.validateManifestDetailed(source)) as ManifestDiagnostic[],
  );
}

/**
 * Validate a manifest AND the Rego it names, returning findings.
 *
 * An empty array means both halves are sound. Each entry has wire
 * shape `{"code","message","severity":"error"}`, matching the C ABI's
 * `acs_artifact_diagnostics`.
 *
 * {@link validateManifestDetailed} answers only for the document. A
 * manifest can satisfy the grammar, name a Rego bundle, and still fail
 * at activation because the Rego does not compile — compilation
 * happens at activation, so a validator that stops at the manifest
 * turns that failure into a host's first agent action. This function
 * activates against `bundles` in memory and reports what the pair
 * surfaced.
 *
 * `bundles` has the same shape {@link ActivatedPolicy.activateFromMemory}
 * takes: a mapping from policy id to a {@link RegoBundle}. Omitting it
 * or passing an empty object means the manifest names no Rego, and the
 * answer then equals what {@link validateManifestDetailed} reports for
 * the manifest half: a document that does not parse is reported as a
 * manifest problem, not an activation problem, because that would name
 * the wrong half.
 *
 * Throws only on boundary problems (non-string manifest, unpaired
 * surrogate, non-object bundles); a broken manifest or Rego module
 * returns a non-empty array.
 */
export function validateArtifacts(
  manifestSource: string,
  bundles?: Readonly<Record<string, RegoBundle>>,
): readonly ManifestDiagnostic[] {
  if (typeof manifestSource !== "string") {
    throw new TypeError(
      `validateArtifacts expects a string manifest, received ${typeof manifestSource}`,
    );
  }
  if (UNPAIRED_SURROGATE.test(manifestSource)) {
    throw new TypeError(
      "validateArtifacts received a manifest with an unpaired surrogate",
    );
  }
  if (bundles !== undefined && (bundles === null || typeof bundles !== "object")) {
    throw new TypeError(
      `validateArtifacts expects bundles to be an object, received ${typeof bundles}`,
    );
  }
  const payload = bundles === undefined ? "" : JSON.stringify(bundles);
  return Object.freeze(
    JSON.parse(
      native.validateArtifactsDetailed(manifestSource, payload),
    ) as ManifestDiagnostic[],
  );
}


// ---------------------------------------------------------------------
// Streaming: incremental release mediation for stream-shaped tracks
// (spec §18.1). The engine is stateless everywhere else; this session
// is the exception, because it accumulates offsets and holds terminal
// state a host must read across many calls.
// ---------------------------------------------------------------------

/** How much a host may release ahead of the watermark. */
export type StreamSafetyLevel = "blocking" | "complete" | "deferred";

/**
 * Role that produced a span of text.
 *
 * Only genuinely rune-addressable roles appear here: tool calls and
 * tool results are structured values evaluated once per invocation and
 * flow through the ordinary snapshot path.
 */
export type StreamSourceType = "user_request" | "model_generated";

/** Independent offset space within a session. */
export type StreamTrack = "request" | "response";

/** What the host decided for one span after evaluating it. */
export type SegmentOutcome = "cleared" | "transformed" | "denied";

/** Parameters a host supplies once, before any payload. */
export interface StreamSessionConfig {
  /** How much the host may release ahead of the watermark. */
  readonly safetyLevel: StreamSafetyLevel;
  /**
   * Offset the first rune of the request track occupies. A retry that
   * resumes a partially delivered stream sets this so offsets stay
   * comparable with the earlier attempt.
   */
  readonly requestStartRuneOffset?: number;
  /** Same as {@link requestStartRuneOffset}, for the response track. */
  readonly responseStartRuneOffset?: number;
  /**
   * Tasks that gate the request track (matching what the host bound at
   * `input`). Empty means the request track is not mediated; payload
   * on it fails closed.
   */
  readonly requestTasks?: readonly string[];
  /**
   * Tasks that gate the response track (matching what the host bound
   * at `post_model_call`). Empty means the response track is not
   * mediated.
   */
  readonly responseTasks?: readonly string[];
}

/** Watermark snapshot for one track. */
export interface StreamWatermarkSnapshot {
  readonly track: StreamTrack;
  /** Highest offset released so far. */
  readonly confirmed: number;
  /** End offset of the text the session has been told about. */
  readonly received: number;
  /**
   * Runes observed but not yet cleared by every task, as of the last
   * advance.
   */
  readonly pending: number;
  /** Task labels this watermark tracks, in deterministic order. */
  readonly tasks: readonly string[];
}

/** Terminal reason a session reached its final state. */
export type StreamEndReason =
  | { readonly kind: "complete" }
  | {
      readonly kind: "denied";
      readonly track: StreamTrack;
      readonly task: string;
      readonly start: number;
      readonly end: number;
    }
  | {
      readonly kind: "rewritten";
      readonly track: StreamTrack;
      readonly task: string;
      readonly start: number;
      readonly end: number;
    }
  | {
      readonly kind: "failed";
      /** The `host_error:*` reason a host records for this failure. */
      readonly reason: string;
      readonly message: string;
    };

/** Terminal settlement of a session. */
export interface StreamCompletion {
  readonly reason: StreamEndReason;
  /**
   * Whether the host emitted a substitute rather than verbatim model
   * output. This is exactly `reason.kind === "rewritten"`.
   */
  readonly transformed: boolean;
  /** Whether the stream finished without an enforcement action. */
  readonly isClean: boolean;
}

/** Read-only view of a session's effective configuration. */
export interface StreamSessionConfigSnapshot {
  readonly safetyLevel: StreamSafetyLevel;
  readonly requestStartRuneOffset: number;
  readonly responseStartRuneOffset: number;
  readonly requestTasks: readonly string[];
  readonly responseTasks: readonly string[];
}

/** Snapshot of a session's state, matching the C ABI `session_state`. */
export interface StreamSessionState {
  readonly isEnded: boolean;
  readonly transformed: boolean;
  /** `null` while the session is still live. */
  readonly endReason: StreamEndReason | null;
  readonly config: StreamSessionConfigSnapshot;
}

/**
 * Incremental streaming session (spec §18.1).
 *
 * ACS is stateless on every other path, so a rune-addressable track a
 * host emits incrementally cannot ride the ordinary interceptor
 * pipeline: a `deny` in the middle of a stream needs to catch a
 * specific range, and a `cleared` prefix needs to release without
 * waiting for the whole payload. This class is the accounting layer
 * that makes both possible.
 *
 * The session holds no policy and no text. The host drives it:
 *
 *  1. Observe arriving text ({@link observe}, {@link observeText}) so
 *     the session knows how many runes exist on each track.
 *  2. Segment the text and evaluate each span with the ordinary
 *     runtime, then record the outcome ({@link recordOutcome}) or
 *     replay the verdict ({@link recordVerdict}).
 *  3. Ask which prefix is safe to release ({@link safeOffset}), and
 *     read {@link watermark} for the per-task frontier when auditing.
 *  4. Call {@link endOfPayloads} at EOF and settle with {@link finish}.
 *
 * A settled session reports `null` from {@link safeOffset} and
 * {@link advance}: the type says "release nothing further" without any
 * value a caller could mistake for a permitted offset. The watermark
 * stays readable so an audit record can still say how far the stream
 * got.
 *
 * Every non-boundary streaming failure (unknown safety level, payload
 * on an unmediated track, offset past the observed end, transform
 * after release, uncleared residue at settlement, ...) throws with the
 * engine's message and puts the session in its terminal `failed`
 * state. The next call sees the session as ended.
 */
/**
 * Refuse a rune offset N-API would silently reshape.
 *
 * N-API converts to `u32` with ToUint32, which wraps rather than fails:
 * `2 ** 32` arrives as `0`, and an end offset of `2 ** 32 + 5` records a
 * *cleared* span of `[0, 5)`, releasing text no task evaluated. Python
 * raises OverflowError and .NET throws OverflowException on the same
 * input, so this is the one language doing modular arithmetic on
 * release accounting.
 */
function runeOffset(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 0x7fffffff) {
    throw new RangeError(`${name} must be a rune offset between 0 and 2147483647, got ${value}`);
  }
  return value;
}

export class StreamSession {
  private readonly handle: unknown;

  /**
   * Open a session.
   *
   * `config.safetyLevel` selects the release rule. `requestTasks` and
   * `responseTasks` are the task labels a host will pass to
   * {@link recordOutcome}: matching a task the manifest binds at
   * `input` / `post_model_call` respectively. An empty task list
   * leaves that track unmediated; payload on it fails closed.
   *
   * Throws when both task lists are empty (the session would gate
   * nothing) or a start offset overflows.
   */
  constructor(config: StreamSessionConfig) {
    if (config === null || typeof config !== "object") {
      throw new TypeError("StreamSession config must be an object");
    }
    const requestStart = config.requestStartRuneOffset ?? 0;
    const responseStart = config.responseStartRuneOffset ?? 0;
    runeOffset(requestStart, 'requestStartRuneOffset');
    runeOffset(responseStart, 'responseStartRuneOffset');
    // Only translate camelCase → wire snake_case here; enum VALUES stay
    // lowercase snake as they arrive.
    const payload = {
      safety_level: config.safetyLevel,
      request_start_rune_offset: requestStart,
      response_start_rune_offset: responseStart,
      request_tasks: config.requestTasks ? Array.from(config.requestTasks) : [],
      response_tasks: config.responseTasks ? Array.from(config.responseTasks) : [],
    };
    this.handle = native.streamSessionNew(JSON.stringify(payload));
  }

  /**
   * Report that `runes` more runes of `sourceType` arrived and return
   * the track's new end offset.
   *
   * This only extends the received bound outcomes are checked against.
   * It does not release anything and does not decide what the host
   * evaluates. Prefer {@link observeText} when the text is at hand:
   * counting runes correctly across surrogate pairs is easy to get
   * wrong.
   */
  observe(sourceType: StreamSourceType, runes: number): number {
    runeOffset(runes, 'runes');
    return native.streamSessionObserve(this.handle, sourceType, runes);
  }

  /**
   * Report arriving `text` on `sourceType`, counting Unicode scalars
   * the way the engine does, and return the track's new end offset.
   *
   * The engine counts runes (Unicode scalars), not UTF-16 code units.
   * An emoji outside the BMP is one rune here even though it is two
   * UTF-16 code units in a JS string.
   */
  observeText(sourceType: StreamSourceType, text: string): number {
    return native.streamSessionObserveText(this.handle, sourceType, text);
  }

  /**
   * Record what `task` decided about the span `[start, end)` of
   * `sourceType`. `outcome` is `cleared`, `transformed`, or `denied`.
   *
   * A `denied` outcome ends the session with `endReason.kind ===
   * "denied"` on the span it refused, and every later `safeOffset`
   * returns `null`. A `transformed` outcome is honored only under a
   * withholding safety level (`blocking` / `complete`) and only while
   * nothing on the track has been released, and it ends the session
   * with `endReason.kind === "rewritten"`.
   */
  recordOutcome(
    task: string,
    sourceType: StreamSourceType,
    start: number,
    end: number,
    outcome: SegmentOutcome,
  ): void {
    runeOffset(start, 'start');
    runeOffset(end, 'end');
    native.streamSessionRecordOutcome(this.handle, task, sourceType, start, end, outcome);
  }

  /**
   * Record an ACS verdict against the span `[start, end)` of
   * `sourceType`, mapping its decision onto an outcome. A host feeds
   * the verdict returned by {@link ActivatedPolicy.evaluate} straight
   * back without translating it.
   *
   * A verdict whose shape section 5 does not admit (a `transform`
   * carrying no transform body, a reserved reason from a policy, ...)
   * fails the stream closed rather than clearing the span.
   */
  recordVerdict(
    task: string,
    sourceType: StreamSourceType,
    start: number,
    end: number,
    verdict: Verdict,
  ): void {
    runeOffset(start, 'start');
    runeOffset(end, 'end');
    native.streamSessionRecordVerdict(
      this.handle,
      task,
      sourceType,
      start,
      end,
      JSON.stringify(verdict),
    );
  }

  /**
   * Recompute `track`'s watermark. Returns the new offset when the
   * watermark advanced, `null` when it did not or the session has
   * ended.
   */
  advance(track: StreamTrack): number | null {
    return native.streamSessionAdvance(this.handle, track);
  }

  /**
   * Offset of `track` the host may release through, or `null` once
   * the session has ended.
   *
   * A settled session has no safe offset: release nothing further.
   * The offset the track reached is unaffected and stays available
   * for an audit record through {@link watermark}.
   */
  safeOffset(track: StreamTrack): number | null {
    return native.streamSessionSafeOffset(this.handle, track);
  }

  /** Runes on `track` observed but not yet released. */
  pending(track: StreamTrack): number {
    return native.streamSessionPending(this.handle, track);
  }

  /**
   * `track`'s watermark, carrying `confirmed`, `received`, `pending`
   * and the `tasks` that must clear it. The confirmed offset stays
   * readable after settlement.
   */
  watermark(track: StreamTrack): StreamWatermarkSnapshot {
    return JSON.parse(native.streamSessionWatermark(this.handle, track)) as StreamWatermarkSnapshot;
  }

  /**
   * Snapshot of session state: `isEnded`, `transformed`, `endReason`
   * (null while live) and the effective `config`.
   */
  state(): StreamSessionState {
    const raw = JSON.parse(native.streamSessionState(this.handle)) as {
      is_ended: boolean;
      transformed: boolean;
      end_reason: StreamEndReason | null;
      config: {
        safety_level: StreamSafetyLevel;
        request_start_rune_offset: number;
        response_start_rune_offset: number;
        request_tasks: string[];
        response_tasks: string[];
      };
    };
    return {
      isEnded: raw.is_ended,
      transformed: raw.transformed,
      endReason: raw.end_reason,
      config: {
        safetyLevel: raw.config.safety_level,
        requestStartRuneOffset: raw.config.request_start_rune_offset,
        responseStartRuneOffset: raw.config.response_start_rune_offset,
        requestTasks: Object.freeze(raw.config.request_tasks),
        responseTasks: Object.freeze(raw.config.response_tasks),
      },
    };
  }

  /** Whether the session has reached its terminal state. */
  isEnded(): boolean {
    return this.state().isEnded;
  }

  /**
   * Terminal reason, when the session has ended, or `null` while it
   * is still live.
   */
  endReason(): StreamEndReason | null {
    return this.state().endReason;
  }

  /**
   * Whether a `transformed` outcome ended this session, meaning the
   * host emits a substitute rather than verbatim model output.
   */
  isTransformed(): boolean {
    return this.state().transformed;
  }

  /**
   * Declare that no further payload will arrive. Idempotent.
   *
   * A `deferred` host calls this at payload EOF so a classifier
   * running behind the stream can still record a denial before
   * {@link finish}.
   */
  endOfPayloads(): void {
    native.streamSessionEndOfPayloads(this.handle);
  }

  /**
   * Settle the session and return the completion.
   *
   * Recomputes both watermarks first, so a host that recorded every
   * outcome is not failed closed for having skipped an explicit
   * {@link advance}. Any rune no task cleared fails the settlement
   * closed. Settling twice returns the same completion.
   */
  finish(): StreamCompletion {
    const raw = JSON.parse(native.streamSessionFinish(this.handle)) as {
      reason: StreamEndReason;
      transformed: boolean;
      is_clean: boolean;
    };
    return {
      reason: raw.reason,
      transformed: raw.transformed,
      isClean: raw.is_clean,
    };
  }
}
