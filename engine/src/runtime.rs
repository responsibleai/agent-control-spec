use crate::{
    annotation::{AnnotatorDispatcher, AnnotatorInvocation},
    constants::{annotation as annotation_key, policy_input as pi_key},
    manifest::Manifest,
    policy::{prepare_policy_invocation, PolicyConfig, PreparedPolicyInvocation},
    policy_input::build_policy_input,
    policy_output::{normalize_policy_output, runtime_error_verdict, EVIDENCE_TRUNCATED_REASON},
    telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetryEventType, TelemetrySink},
    tool_projection::project_tool,
    JsonPath, JsonValue, Limits, PathEnv, PerfTelemetry, RuntimeError,
};
use agent_hooks::{InterceptionPoint, Verdict};
use serde_json::Map;
use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    time::Instant,
};

pub trait PolicyDispatcher: Send + Sync {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError>;

    /// Do whatever work for `invocation` can be done before a decision is
    /// needed: parse the bundle, compile the policy, cache the result.
    ///
    /// Called once per intervention point by
    /// [`crate::ActivatedPolicy::activate`], so that the cost of readying
    /// a policy version is paid at activation rather than charged to the
    /// first agent action, and never charged again.
    ///
    /// A dispatcher that has nothing to prepare keeps the default no-op.
    /// Warming is an optimization, so a failure here is reported to the
    /// caller of `activate` but never changes a later verdict: an
    /// unwarmed policy still evaluates, just more slowly.
    fn warm(&self, _invocation: &PreparedPolicyInvocation) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct Runtime {
    manifest: Manifest,
    annotation_plans: BTreeMap<InterceptionPoint, AnnotationPlan>,
    annotations: Arc<dyn AnnotatorDispatcher>,
    policy: Arc<dyn PolicyDispatcher>,
    telemetry: Arc<dyn TelemetrySink>,
    perf_telemetry: PerfTelemetry,
    limits: Limits,
}

#[derive(Clone)]
struct AnnotationDependencies {
    names: Vec<String>,
    metadata: String,
}

#[derive(Clone)]
struct AnnotationPlan {
    order: Vec<String>,
    dependencies: BTreeMap<String, AnnotationDependencies>,
}

impl AnnotationPlan {
    fn prepare(
        point: InterceptionPoint,
        config: &crate::manifest::InterventionPointConfig,
        manifest: &Manifest,
    ) -> Result<Self, RuntimeError> {
        let order = crate::manifest::annotation_dispatch_order(point, config, manifest)?;
        let mut dependencies = BTreeMap::new();
        for (name, annotation) in &config.annotations {
            let names: Vec<String> = manifest
                .annotation_dependencies(annotation)?
                .into_iter()
                .map(str::to_string)
                .collect();
            if names.is_empty() {
                continue;
            }
            let metadata = serde_json::to_string(&names).map_err(|error| {
                RuntimeError::ManifestInvalid(format!(
                    "cannot serialize dependencies for annotation '{name}': {error}"
                ))
            })?;
            dependencies.insert(name.clone(), AnnotationDependencies { names, metadata });
        }
        Ok(Self {
            order,
            dependencies,
        })
    }
}

impl Runtime {
    pub fn new(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
    ) -> Result<Self, RuntimeError> {
        let telemetry: Arc<dyn TelemetrySink> = Arc::new(NoopTelemetrySink);
        Self::with_telemetry_and_perf(
            manifest,
            annotations,
            policy,
            telemetry,
            PerfTelemetry::default(),
        )
    }

    pub fn with_perf_telemetry(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        perf_telemetry: PerfTelemetry,
    ) -> Result<Self, RuntimeError> {
        let telemetry: Arc<dyn TelemetrySink> = Arc::new(NoopTelemetrySink);
        Self::with_telemetry_and_perf(manifest, annotations, policy, telemetry, perf_telemetry)
    }

    pub fn with_limits(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        let telemetry: Arc<dyn TelemetrySink> = Arc::new(NoopTelemetrySink);
        Self::with_telemetry_perf_and_limits(
            manifest,
            annotations,
            policy,
            telemetry,
            PerfTelemetry::default(),
            limits,
        )
    }

    pub fn with_telemetry(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        telemetry: Arc<dyn TelemetrySink>,
    ) -> Result<Self, RuntimeError> {
        Self::with_telemetry_and_perf(
            manifest,
            annotations,
            policy,
            telemetry,
            PerfTelemetry::default(),
        )
    }

    pub fn with_telemetry_and_perf(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        telemetry: Arc<dyn TelemetrySink>,
        perf_telemetry: PerfTelemetry,
    ) -> Result<Self, RuntimeError> {
        Self::with_telemetry_perf_and_limits(
            manifest,
            annotations,
            policy,
            telemetry,
            perf_telemetry,
            Limits::default(),
        )
    }

    pub fn with_telemetry_perf_and_limits(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        telemetry: Arc<dyn TelemetrySink>,
        perf_telemetry: PerfTelemetry,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        manifest.validate()?;
        if !manifest.extends.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "manifest 'extends' was not resolved; an enforcing runtime requires a fully \
                 composed manifest. Compose with Manifest::from_path, Manifest::from_yaml_chain, \
                 acs_builder_from_path, or acs_builder_from_yaml_chain; single-string loaders \
                 must be given an already-merged manifest"
                    .to_string(),
            ));
        }
        let annotation_plans = manifest
            .intervention_points
            .iter()
            .map(|(point, config)| {
                AnnotationPlan::prepare(*point, config, &manifest).map(|plan| (*point, plan))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            manifest,
            annotation_plans,
            annotations,
            policy,
            telemetry,
            perf_telemetry,
            limits,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The policy dispatcher this runtime evaluates through. Exposed so
    /// activation can ready each bound policy ahead of the first
    /// decision.
    pub fn policy_dispatcher(&self) -> &Arc<dyn PolicyDispatcher> {
        &self.policy
    }

    pub fn perf_telemetry(&self) -> PerfTelemetry {
        self.perf_telemetry
    }

    pub fn with_perf_telemetry_level(mut self, perf_telemetry: PerfTelemetry) -> Self {
        self.perf_telemetry = perf_telemetry;
        self
    }

    /// Evaluate an agent-hooks context, resolving the interception
    /// point from its required `interception_point` member.
    pub fn evaluate(&self, snapshot: &JsonValue) -> EvaluationResult {
        let point = snapshot
            .get("interception_point")
            .and_then(JsonValue::as_str)
            .and_then(|name| name.parse::<InterceptionPoint>().ok());
        match point {
            Some(point) => self.evaluate_point(point, snapshot.clone()),
            None => EvaluationResult {
                verdict: runtime_error_verdict(&RuntimeError::InterventionPointUnknown(
                    "context carries no valid interception_point".to_string(),
                )),
                policy_input: None,
            },
        }
    }

    /// Evaluate one interception point against a context snapshot.
    pub fn evaluate_point(
        &self,
        intervention_point: InterceptionPoint,
        snapshot: JsonValue,
    ) -> EvaluationResult {
        let request = EvaluationRequest {
            intervention_point,
            snapshot,
        };
        let started_at = Instant::now();
        let policy_id = self.policy_id_for(intervention_point).map(str::to_string);
        let annotators = self.annotators_for(intervention_point);
        let result = match self.evaluate_inner(request) {
            Ok(result) => result,
            Err(failure) => EvaluationResult {
                verdict: runtime_error_verdict(&failure.error),
                policy_input: failure.policy_input,
            },
        };
        let duration_ms = started_at.elapsed().as_secs_f64() * 1000.0;
        self.emit_decision_event(
            intervention_point,
            &result.verdict,
            policy_id.as_deref(),
            annotators,
            duration_ms,
            None,
        );
        if self.perf_telemetry.emit_stage_events() {
            self.emit_event(
                TelemetryEvent::new(TelemetryEventType::EvaluationTiming, intervention_point)
                    .with_decision(result.verdict.decision)
                    .with_optional_reason_code(
                        safe_telemetry_reason_code(result.verdict.reason.as_deref()).as_deref(),
                    )
                    .with_optional_policy_id(policy_id.as_deref())
                    .with_optional_error_class(
                        telemetry_error_class(result.verdict.reason.as_deref()).as_deref(),
                    )
                    .with_duration_ms(duration_ms)
                    .with_optional_action_identity(None),
            );
        }
        result
    }

    fn evaluate_inner(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResult, EvaluationFailure> {
        let point_config = self
            .manifest
            .intervention_points
            .get(&request.intervention_point)
            .ok_or_else(|| {
                RuntimeError::InterventionPointUnknown(
                    request.intervention_point.as_str().to_string(),
                )
            })?;

        self.limits.validate_snapshot(&request.snapshot)?;

        let policy_target_field = point_config.policy_target.as_str();
        let policy = &point_config.policy;

        let policy_target_path =
            JsonPath::parse_with_snapshot_alias(policy_target_field).map_err(|err| {
                RuntimeError::ManifestInvalid(format!(
                    "invalid policy_target for intervention point {}: {err}",
                    request.intervention_point
                ))
            })?;
        let policy_target = policy_target_path.resolve(&PathEnv::with_snap(&request.snapshot))?;
        let tool = project_tool(
            &self.manifest,
            request.intervention_point,
            point_config,
            &request.snapshot,
        )?;

        let preliminary_policy_input = build_policy_input(
            request.intervention_point,
            policy_target_field,
            point_config.policy_target_kind.as_deref(),
            policy_target.clone(),
            request.snapshot.clone(),
            JsonValue::Object(Map::new()),
            tool.clone(),
        );
        self.limits
            .validate_policy_input(&preliminary_policy_input)?;

        let annotations = self
            .collect_annotations(
                request.intervention_point,
                point_config,
                &preliminary_policy_input,
            )
            .map_err(|error| EvaluationFailure {
                error,
                policy_input: Some(preliminary_policy_input.clone()),
            })?;

        let final_policy_input = build_policy_input(
            request.intervention_point,
            policy_target_field,
            point_config.policy_target_kind.as_deref(),
            policy_target.clone(),
            request.snapshot.clone(),
            annotations,
            tool,
        );
        self.limits.validate_policy_input(&final_policy_input)?;

        let policy_config = self.manifest.policies.get(&policy.id).ok_or_else(|| {
            RuntimeError::ManifestInvalid(format!(
                "intervention point {} references unknown policy '{}'",
                request.intervention_point, policy.id
            ))
        })?;

        let invocation = prepare_policy_invocation(policy_config, policy, &final_policy_input)
            .map_err(|error| {
                self.emit_policy_failed(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    &error,
                );
                EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                }
            })?;

        let policy_start = Instant::now();
        let policy_output = catch_unwind(AssertUnwindSafe(|| self.policy.evaluate(&invocation)))
            .map_err(|payload| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "policy dispatcher panicked: {}",
                    panic_detail(payload.as_ref())
                ))
            })
            .and_then(|result| {
                result.map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))
            })
            .map_err(|error| {
                self.emit_policy_external_event(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    Some(error.reason()),
                    policy_start.elapsed().as_secs_f64() * 1000.0,
                );
                self.emit_policy_failed(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    &error,
                );
                EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                }
            })?;
        self.emit_policy_external_event(
            request.intervention_point,
            &policy.id,
            policy_config,
            None,
            policy_start.elapsed().as_secs_f64() * 1000.0,
        );

        self.limits
            .validate_policy_output(&policy_output)
            .map_err(|error| {
                self.emit_policy_failed(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    &error,
                );
                EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                }
            })?;

        let verdict = normalize_policy_output(policy_output).map_err(|error| {
            self.emit_policy_failed(
                request.intervention_point,
                &policy.id,
                policy_config,
                &error,
            );
            EvaluationFailure {
                error,
                policy_input: Some(final_policy_input.clone()),
            }
        })?;

        // Transform application, enforcement mode, approval resolution,
        // and identity computation are host obligations under
        // AGENT-HOOKS-0.1 (§6, §8, §9, §10); the engine returns the
        // verdict and the policy input it evaluated.
        Ok(EvaluationResult {
            verdict,
            policy_input: Some(final_policy_input),
        })
    }

    fn collect_annotations(
        &self,
        intervention_point: InterceptionPoint,
        point_config: &crate::manifest::InterventionPointConfig,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        if point_config.annotations.len() > self.limits.max_annotators_per_point {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "intervention point {} invokes {} annotators, limit {}",
                intervention_point,
                point_config.annotations.len(),
                self.limits.max_annotators_per_point
            )));
        }

        let plan = self
            .annotation_plans
            .get(&intervention_point)
            .ok_or_else(|| {
                RuntimeError::ManifestInvalid(format!(
                    "missing annotation plan for {intervention_point}"
                ))
            })?;
        let mut annotations_map = Map::new();
        // Reuse one request-local copy; callbacks only borrow it immutably.
        let mut staged_policy_input: Option<JsonValue> = None;
        for annotator_name in &plan.order {
            let annotation_config = point_config
                .annotations
                .get(annotator_name)
                .ok_or_else(|| RuntimeError::ManifestInvalid(annotator_name.clone()))
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            let annotator_config = self
                .manifest
                .annotators
                .get(annotator_name)
                .ok_or_else(|| RuntimeError::ManifestInvalid(annotator_name.clone()))
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            let annotator = AnnotatorInvocation::from_annotation_in(
                &self.manifest,
                annotator_config,
                annotation_config,
            );

            // Each callback sees only its declared dependencies.
            let dispatch_input = if let Some(dependencies) = plan.dependencies.get(annotator_name) {
                let mut visible = Map::new();
                for need in &dependencies.names {
                    let result = annotations_map
                        .get(need)
                        .cloned()
                        .ok_or_else(|| {
                            RuntimeError::ManifestInvalid(format!(
                                "annotator '{annotator_name}' needs '{need}', which has not run"
                            ))
                        })
                        .inspect_err(|error| {
                            self.emit_annotator_failed(intervention_point, annotator_name, error);
                        })?;
                    visible.insert(need.clone(), result);
                }
                let staged =
                    staged_policy_input.get_or_insert_with(|| preliminary_policy_input.clone());
                let object = staged
                    .as_object_mut()
                    .ok_or_else(|| {
                        RuntimeError::ManifestInvalid(
                            "preliminary policy input is not an object".to_string(),
                        )
                    })
                    .inspect_err(|error| {
                        self.emit_annotator_failed(intervention_point, annotator_name, error);
                    })?;
                let visible = JsonValue::Object(visible);
                self.limits
                    .validate_policy_annotations(&visible)
                    .inspect_err(|error| {
                        self.emit_annotator_failed(intervention_point, annotator_name, error);
                    })?;
                object.insert(pi_key::ANNOTATIONS.to_string(), visible);
                &*staged
            } else {
                preliminary_policy_input
            };

            if let Some(input_from) = annotator.input_from() {
                let path = JsonPath::parse_with_snapshot_alias(input_from)
                    .map_err(|err| {
                        RuntimeError::ManifestInvalid(format!(
                            "invalid from path for annotator '{annotator_name}': {err}"
                        ))
                    })
                    .inspect_err(|error| {
                        self.emit_annotator_failed(intervention_point, annotator_name, error);
                    })?;
                let snapshot = dispatch_input.get(pi_key::SNAPSHOT).ok_or_else(|| {
                    RuntimeError::ManifestInvalid(
                        "preliminary policy input missing snapshot".to_string(),
                    )
                })?;
                path.resolve(&PathEnv::with_pi_and_snap(dispatch_input, snapshot))
                    .inspect_err(|error| {
                        self.emit_annotator_failed(intervention_point, annotator_name, error);
                    })?;
            }

            let dispatch_start = Instant::now();
            let output = catch_unwind(AssertUnwindSafe(|| {
                self.annotations
                    .dispatch(annotator_name, &annotator, dispatch_input)
            }))
            .map_err(|payload| {
                RuntimeError::AnnotationFailed(format!(
                    "annotator dispatcher panicked: {}",
                    panic_detail(payload.as_ref())
                ))
            })
            .and_then(|result| result)
            .map_err(|err| normalize_annotator_error(annotator_name, err))
            .inspect_err(|error| {
                self.emit_annotator_external_event(
                    intervention_point,
                    annotator_name,
                    Some(error.reason()),
                    dispatch_start.elapsed().as_secs_f64() * 1000.0,
                );
                self.emit_annotator_failed(intervention_point, annotator_name, error);
            })?;
            self.limits
                .validate_annotator_output(annotator_name, &output)
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            self.emit_annotator_external_event(
                intervention_point,
                annotator_name,
                None,
                dispatch_start.elapsed().as_secs_f64() * 1000.0,
            );
            annotations_map.insert(annotator_name.clone(), output);
        }
        Ok(JsonValue::Object(annotations_map))
    }

    // AGT integration passes decision evidence/identity fields explicitly; keep
    // the signature stable to minimize divergence and risk in the vendored
    // runtime hot path rather than refactoring to a params struct.
    #[allow(clippy::too_many_arguments)]
    fn emit_decision_event(
        &self,
        intervention_point: InterceptionPoint,
        verdict: &Verdict,
        policy_id: Option<&str>,
        annotators: Vec<String>,
        duration_ms: f64,
        action_identity: Option<&str>,
    ) {
        // AGT D2 / AGT-EVIDENCE-1.0 §3: propagate the verbatim artefact
        // string and the sorted pointer keys (not URL values) when the
        // verdict carries `evidence`.
        let (evidence_artefact, evidence_keys): (Option<String>, Vec<String>) =
            match verdict.evidence.as_ref() {
                Some(evidence) => (
                    evidence.artefact.clone(),
                    evidence.verification_pointers.keys().cloned().collect(),
                ),
                None => (None, Vec::new()),
            };

        // Section 13.3: when the runtime degraded the evidence, the keys
        // above are the kept subset. Mark the event so a consumer does
        // not read them as the whole map. The runtime owns the marker
        // reason, so its presence on the verdict is the runtime's own
        // statement and not a dispatcher's.
        let evidence_truncated = verdict
            .warnings
            .iter()
            .any(|warning| warning.reason.as_deref() == Some(EVIDENCE_TRUNCATED_REASON));
        let mark_evidence = |event: TelemetryEvent| {
            if evidence_truncated {
                event.with_metadata(EVIDENCE_TRUNCATED_REASON, "true")
            } else {
                event
            }
        };

        self.emit_event(mark_evidence(
            TelemetryEvent::new(TelemetryEventType::Decision, intervention_point)
                .with_decision(verdict.decision)
                .with_optional_reason_code(
                    safe_telemetry_reason_code(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_error_class(
                    telemetry_error_class(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_policy_id(policy_id)
                .with_annotators(annotators.clone())
                .with_duration_ms(duration_ms)
                .with_optional_action_identity(action_identity)
                .with_evidence(evidence_artefact.as_deref(), evidence_keys.clone()),
        ));

        // AGT D2: when the decision is `Transform`, emit the dedicated
        // `intervention_point.transformed` event in addition to the
        // base Decision event so that single-event consumers and
        // multi-event consumers both see the transformation.
        if verdict.decision == agent_hooks::Decision::Transform {
            self.emit_event(mark_evidence(
                TelemetryEvent::new(
                    TelemetryEventType::InterventionPointTransformed,
                    intervention_point,
                )
                .with_decision(verdict.decision)
                .with_optional_reason_code(
                    safe_telemetry_reason_code(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_error_class(
                    telemetry_error_class(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_policy_id(policy_id)
                .with_annotators(annotators)
                .with_duration_ms(duration_ms)
                .with_optional_action_identity(action_identity)
                .with_evidence(evidence_artefact.as_deref(), evidence_keys),
            ));
        }
    }

    /// Cached names only; no result values enter dependency metadata.
    fn annotation_needs(
        &self,
        intervention_point: InterceptionPoint,
        annotator_name: &str,
    ) -> Option<&str> {
        self.annotation_plans
            .get(&intervention_point)?
            .dependencies
            .get(annotator_name)
            .map(|dependencies| dependencies.metadata.as_str())
    }

    fn emit_annotator_failed(
        &self,
        intervention_point: InterceptionPoint,
        annotator_name: &str,
        error: &RuntimeError,
    ) {
        let mut event =
            TelemetryEvent::new(TelemetryEventType::AnnotatorFailed, intervention_point)
                .with_annotator(annotator_name)
                .with_reason_code(error.reason())
                .with_optional_error_class(telemetry_error_class(Some(error.reason())).as_deref());
        if let Some(needs) = self.annotation_needs(intervention_point, annotator_name) {
            event = event.with_metadata(annotation_key::NEEDS, needs);
        }
        self.emit_event(event);
    }

    fn emit_policy_failed(
        &self,
        intervention_point: InterceptionPoint,
        policy_id: &str,
        policy_config: &PolicyConfig,
        error: &RuntimeError,
    ) {
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::PolicyFailed, intervention_point)
                .with_policy_id(policy_id)
                .with_reason_code(error.reason())
                .with_optional_error_class(telemetry_error_class(Some(error.reason())).as_deref())
                .with_metadata("policy_type", policy_config.engine_type()),
        );
    }

    fn emit_annotator_external_event(
        &self,
        intervention_point: InterceptionPoint,
        annotator_name: &str,
        reason: Option<&str>,
        duration_ms: f64,
    ) {
        if !self.perf_telemetry.emit_external_events() {
            return;
        }
        let mut event =
            TelemetryEvent::new(TelemetryEventType::AnnotatorDispatch, intervention_point)
                .with_annotator(annotator_name)
                .with_optional_reason_code(safe_telemetry_reason_code(reason).as_deref())
                .with_optional_error_class(telemetry_error_class(reason).as_deref())
                .with_duration_ms(duration_ms);
        if let Some(needs) = self.annotation_needs(intervention_point, annotator_name) {
            event = event.with_metadata(annotation_key::NEEDS, needs);
        }
        self.emit_event(event);
    }

    fn emit_policy_external_event(
        &self,
        intervention_point: InterceptionPoint,
        policy_id: &str,
        policy_config: &PolicyConfig,
        reason: Option<&str>,
        duration_ms: f64,
    ) {
        if !self.perf_telemetry.emit_external_events() {
            return;
        }
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::PolicyEvaluation, intervention_point)
                .with_policy_id(policy_id)
                .with_optional_reason_code(safe_telemetry_reason_code(reason).as_deref())
                .with_optional_error_class(telemetry_error_class(reason).as_deref())
                .with_duration_ms(duration_ms)
                .with_metadata("policy_type", policy_config.engine_type()),
        );
    }

    fn emit_event(&self, event: TelemetryEvent) {
        let _ = catch_unwind(AssertUnwindSafe(|| self.telemetry.emit(event)));
    }

    fn policy_id_for(&self, intervention_point: InterceptionPoint) -> Option<&str> {
        self.manifest
            .intervention_points
            .get(&intervention_point)
            .map(|config| config.policy.id.as_str())
    }

    fn annotators_for(&self, intervention_point: InterceptionPoint) -> Vec<String> {
        self.manifest
            .intervention_points
            .get(&intervention_point)
            .map(|config| config.annotations.keys().cloned().collect())
            .unwrap_or_default()
    }
}

fn safe_telemetry_reason_code(reason: Option<&str>) -> Option<String> {
    let reason = reason?;
    if is_identifier_reason_code(reason) {
        Some(reason.to_string())
    } else {
        Some("policy_reason".to_string())
    }
}

fn telemetry_error_class(reason: Option<&str>) -> Option<String> {
    reason
        .filter(|reason| reason.starts_with("runtime_error:"))
        .map(|_| "runtime_error".to_string())
}

fn is_identifier_reason_code(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 96
        && reason.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[derive(Debug, Clone)]
pub struct EvaluationRequest {
    pub intervention_point: InterceptionPoint,
    pub snapshot: JsonValue,
}

/// Result of evaluating a single intervention point.
///
/// Per AGT D1.4 the engine produces two SHA-256 identities for every
/// successful evaluation:
///
/// - `input_identity` pins what the policy actually saw.
/// - `enforced_identity` pins what the host will carry out. It differs
///   from `input_identity` only when the verdict is `Decision::Transform`
///   in `EnforcementMode::Enforce`; in every other case the two are equal.
///
/// `action_identity` is retained as a backwards-compatible alias that
/// always equals `enforced_identity`, satisfying the AGT-EVIDENCE-1.0
/// note that single-identity telemetry consumers MAY default to
/// `enforced_identity`. New callers should reach for the bisected fields
/// directly.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationResult {
    /// The agent-hooks verdict the host must honour. Always present:
    /// evaluation failures surface as fail-closed `deny` verdicts with
    /// `runtime_error:*` reasons, never as errors.
    pub verdict: Verdict,
    /// The final policy input the dispatcher evaluated, when one was
    /// constructed. Diagnostic; not part of the host contract.
    pub policy_input: Option<JsonValue>,
}

fn normalize_annotator_error(annotator_name: &str, error: RuntimeError) -> RuntimeError {
    match error {
        RuntimeError::AnnotationTimeout(detail) => {
            RuntimeError::AnnotationTimeout(annotator_error_detail(annotator_name, detail))
        }
        RuntimeError::AnnotationFailed(detail) => {
            RuntimeError::AnnotationFailed(annotator_error_detail(annotator_name, detail))
        }
        other => RuntimeError::AnnotationFailed(format!("{annotator_name}: {other}")),
    }
}

fn annotator_error_detail(annotator_name: &str, detail: String) -> String {
    if detail.is_empty() || detail == annotator_name {
        annotator_name.to_string()
    } else if detail.starts_with(&format!("{annotator_name}:")) {
        detail
    } else {
        format!("{annotator_name}: {detail}")
    }
}

#[derive(Debug)]
struct EvaluationFailure {
    error: RuntimeError,
    policy_input: Option<JsonValue>,
}

impl From<RuntimeError> for EvaluationFailure {
    fn from(error: RuntimeError) -> Self {
        Self {
            error,
            policy_input: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use agent_hooks::Decision;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct StaticAnnotator;
    impl crate::annotation::AnnotatorDispatcher for StaticAnnotator {
        fn dispatch(
            &self,
            _annotator_name: &str,
            _annotator: &crate::annotation::AnnotatorInvocation,
            _preliminary_policy_input: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            Ok(JsonValue::Null)
        }
    }

    struct StaticPolicy {
        output: JsonValue,
        seen: Mutex<Vec<JsonValue>>,
    }

    impl PolicyDispatcher for StaticPolicy {
        fn evaluate(
            &self,
            invocation: &crate::policy::PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            self.seen
                .lock()
                .unwrap()
                .push(invocation.policy_input().unwrap().clone());
            Ok(self.output.clone())
        }
    }

    #[test]
    fn every_supported_contract_drives_the_declared_annotation_semantics() {
        struct Recording(Mutex<Vec<(String, bool, JsonValue)>>);
        impl AnnotatorDispatcher for Recording {
            fn dispatch(
                &self,
                name: &str,
                invocation: &AnnotatorInvocation,
                input: &JsonValue,
            ) -> Result<JsonValue, RuntimeError> {
                self.0.lock().unwrap().push((
                    name.into(),
                    invocation.field("needs").is_some(),
                    input["annotations"].clone(),
                ));
                Ok(json!({"value": 1}))
            }
        }
        for version in crate::SUPPORTED_VERSIONS {
            let contract = crate::constants::manifest_version::contract(version).unwrap();
            let manifest = Manifest::from_json_str(
                &json!({
                    "agent_control_specification_version": version,
                    "policies": {"p": {"type": "test"}},
                    "annotators": {"alpha": {"type": "classifier"}, "zeta": {"type": "classifier"}},
                    "intervention_points": {"input": {
                        "policy_target": "$snap.input", "policy": {"id": "p"},
                        "annotations": {
                            "alpha": {"needs": ["zeta"], "from": "$target"},
                            "zeta": {"from": "$target"}
                        }
                    }}
                })
                .to_string(),
            )
            .unwrap();
            let recorder = Arc::new(Recording(Mutex::new(vec![])));
            let runtime = Runtime::new(
                manifest,
                recorder.clone(),
                Arc::new(StaticPolicy {
                    output: json!({"decision":"allow"}),
                    seen: Mutex::new(vec![]),
                }),
            )
            .unwrap();
            let result =
                runtime.evaluate_point(InterceptionPoint::Input, json!({"input": "value"}));
            assert_eq!(result.verdict.decision, Decision::Allow);
            let calls = recorder.0.lock().unwrap();
            if contract.annotation_chaining {
                assert_eq!(calls[0].0, "zeta");
                assert_eq!(
                    calls[1],
                    ("alpha".into(), false, json!({"zeta": {"value":1}}))
                );
            } else {
                assert_eq!(calls[0], ("alpha".into(), true, json!({})));
                assert_eq!(calls[1].0, "zeta");
            }
        }
    }

    #[test]
    fn staging_reuses_one_snapshot_copy_without_exposing_stale_dependencies() {
        struct Recording(Mutex<Vec<(String, usize, JsonValue, JsonValue)>>);
        impl AnnotatorDispatcher for Recording {
            fn dispatch(
                &self,
                name: &str,
                _: &AnnotatorInvocation,
                input: &JsonValue,
            ) -> Result<JsonValue, RuntimeError> {
                self.0.lock().unwrap().push((
                    name.into(),
                    std::ptr::from_ref(&input["snapshot"]) as usize,
                    input["annotations"].clone(),
                    input["snapshot"].clone(),
                ));
                Ok(json!({"request": input["snapshot"]["input"]}))
            }
        }
        let manifest = Manifest::from_json_str(&json!({
            "agent_control_specification_version": crate::constants::manifest_version::ANNOTATION_CHAINING,
            "policies": {"p": {"type": "test"}},
            "annotators": {
                "alpha": {"type": "classifier"}, "beta": {"type": "classifier"},
                "gamma": {"type": "classifier"}, "zeta": {"type": "classifier"}
            },
            "intervention_points": {"input": {
                "policy_target": "$snap.input", "policy": {"id":"p"},
                "annotations": {
                    "alpha": {"from":"$target"},
                    "beta": {"needs":["alpha"], "from":"$target"},
                    "gamma": {"from":"$target"},
                    "zeta": {"needs":["beta"], "from":"$target"}
                }
            }}
        }).to_string()).unwrap();
        let recorder = Arc::new(Recording(Mutex::new(vec![])));
        let runtime = Runtime::new(
            manifest,
            recorder.clone(),
            Arc::new(StaticPolicy {
                output: json!({"decision":"allow"}),
                seen: Mutex::new(vec![]),
            }),
        )
        .unwrap();
        for request in ["first", "second"] {
            assert_eq!(
                runtime
                    .evaluate_point(InterceptionPoint::Input, json!({"input":request}))
                    .verdict
                    .decision,
                Decision::Allow
            );
            let mut calls = recorder.0.lock().unwrap();
            assert_eq!(
                calls.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
                ["alpha", "beta", "gamma", "zeta"]
            );
            assert_eq!(
                calls[1].1, calls[3].1,
                "dependent callbacks reuse the snapshot copy"
            );
            assert_eq!(
                calls[2].2,
                json!({}),
                "an independent callback sees no prior outputs"
            );
            assert_eq!(calls[3].2, json!({"beta":{"request":request}}));
            for call in calls.iter() {
                assert_eq!(call.3, json!({"input":request}));
            }
            calls.clear();
        }
        let plan = &runtime.annotation_plans[&InterceptionPoint::Input];
        assert_eq!(plan.order, ["alpha", "beta", "gamma", "zeta"]);
        assert_eq!(plan.dependencies["beta"].metadata, "[\"alpha\"]");
    }

    fn runtime(policy_output: JsonValue) -> Runtime {
        let manifest = Manifest::from_yaml_str(
            r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output"#,
        )
        .unwrap();
        Runtime::new(
            manifest,
            Arc::new(StaticAnnotator),
            Arc::new(StaticPolicy {
                output: policy_output,
                seen: Mutex::new(Vec::new()),
            }),
        )
        .unwrap()
    }

    fn ctx(point: &str, body: JsonValue) -> JsonValue {
        json!({
            "spec": "agent-hooks/0.1",
            "interception_point": point,
            "timestamp": "2026-01-01T00:00:00Z",
            "sequence": 1,
            "agent": {"id": "a", "framework": "test"},
            "session": {"id": "s"},
            "input": body,
            "output": body,
            "target": body,
        })
    }

    #[test]
    fn allow_passes_through() {
        let result =
            runtime(json!({"decision": "allow"})).evaluate(&ctx("input", json!({"message": "hi"})));
        assert_eq!(result.verdict.decision, Decision::Allow);
        assert!(result.policy_input.is_some());
    }

    #[test]
    fn warn_intent_becomes_allow_with_warning() {
        let result = runtime(json!({
            "decision": "warn",
            "reason": "needs_review",
            "message": "proceeding with caution"
        }))
        .evaluate(&ctx("input", json!({"message": "hi"})));
        assert_eq!(result.verdict.decision, Decision::Allow);
        assert_eq!(result.verdict.warnings.len(), 1);
        assert_eq!(
            result.verdict.warnings[0].reason.as_deref(),
            Some("needs_review")
        );
    }

    #[test]
    fn escalate_intent_becomes_liftable_deny() {
        let result = runtime(json!({"decision": "escalate", "reason": "human_gate"}))
            .evaluate(&ctx("input", json!({"message": "hi"})));
        assert_eq!(result.verdict.decision, Decision::Deny);
        assert!(result.verdict.is_liftable());
        assert_eq!(result.verdict.reason.as_deref(), Some("human_gate"));
    }

    #[test]
    fn transform_is_returned_unapplied() {
        let result = runtime(json!({
            "decision": "transform",
            "transform": {"path": "$target.message", "value": "[REDACTED]"}
        }))
        .evaluate(&ctx("output", json!({"message": "secret"})));
        assert_eq!(result.verdict.decision, Decision::Transform);
        let transform = result.verdict.transform.as_ref().unwrap();
        assert_eq!(transform.path, "$target.message");
        // The engine never rewrites the context: transform application
        // is a host obligation.
        assert_eq!(
            result.policy_input.unwrap()["policy_target"]["value"],
            json!({"message": "secret"})
        );
    }

    #[test]
    fn context_without_point_fails_closed() {
        let result = runtime(json!({"decision": "allow"})).evaluate(&json!({"input": {}}));
        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:intervention_point_unknown")
        );
    }

    #[test]
    fn unbound_point_fails_closed() {
        let result =
            runtime(json!({"decision": "allow"})).evaluate(&ctx("pre_tool_call", json!({})));
        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:intervention_point_unknown")
        );
    }

    #[test]
    fn reserved_reason_from_policy_fails_closed() {
        let result = runtime(json!({"decision": "allow", "reason": "host_error:context_invalid"}))
            .evaluate(&ctx("input", json!({})));
        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:policy_output_invalid")
        );
    }
}
