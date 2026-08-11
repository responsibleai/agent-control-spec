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
    // Only translate camelCase → wire snake_case here; enum VALUES stay
    // lowercase snake as they arrive.
    const payload = {
      safety_level: config.safetyLevel,
      request_start_rune_offset: config.requestStartRuneOffset ?? 0,
      response_start_rune_offset: config.responseStartRuneOffset ?? 0,
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
