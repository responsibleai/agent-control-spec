//! Request-local resolution for callable annotations. Provider results never
//! enter a prepared policy cache or mutate the Rego input.

use crate::{InterceptionPoint, JsonValue, Runtime, RuntimeError};
use serde::Serialize;
use serde_json::{json, Map};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
pub struct AnnotationResolution {
    pub status: &'static str,
    pub provider_calls: usize,
    pub cache_hits: usize,
    pub skipped_calls: usize,
    pub failure_reason: Option<String>,
}

struct State {
    values: Map<String, JsonValue>,
    reports: BTreeMap<String, AnnotationResolution>,
    failure: Option<RuntimeError>,
    deadline: Option<Instant>,
    closed: bool,
    resolving: bool,
}

struct Context {
    runtime: Runtime,
    point: InterceptionPoint,
    input: JsonValue,
    state: Mutex<State>,
}

/// A capability scoped to one runtime evaluation. Custom policy dispatchers
/// must preserve errors and must not retain this handle after evaluation.
#[derive(Clone)]
pub struct OnDemandAnnotations(Arc<Context>);

impl OnDemandAnnotations {
    pub(crate) fn new(
        runtime: Runtime,
        point: InterceptionPoint,
        input: JsonValue,
    ) -> Result<Self, RuntimeError> {
        let config = runtime
            .manifest()
            .intervention_points
            .get(&point)
            .ok_or_else(|| RuntimeError::ManifestInvalid("missing intervention point".into()))?;
        let mut reports = BTreeMap::new();
        for (name, binding) in &config.annotations {
            if runtime.manifest().annotation_is_on_demand(binding)? {
                reports.insert(
                    name.clone(),
                    AnnotationResolution {
                        status: "unrequested",
                        provider_calls: 0,
                        cache_hits: 0,
                        skipped_calls: 0,
                        failure_reason: None,
                    },
                );
            }
        }
        let values = input
            .get("annotations")
            .and_then(JsonValue::as_object)
            .cloned()
            .ok_or_else(|| RuntimeError::ManifestInvalid("missing annotations object".into()))?;
        Ok(Self(Arc::new(Context {
            runtime,
            point,
            input,
            state: Mutex::new(State {
                values,
                reports,
                failure: None,
                deadline: None,
                closed: false,
                resolving: false,
            }),
        })))
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, RuntimeError> {
        self.0.state.lock().map_err(|_| {
            RuntimeError::PolicyInvocationFailed("on-demand annotation state is poisoned".into())
        })
    }

    fn check_live(state: &State) -> Result<(), RuntimeError> {
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        if state.closed
            || state
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(RuntimeError::PolicyInvocationFailed(
                "on-demand evaluation is closed or its deadline expired".into(),
            ));
        }
        Ok(())
    }

    /// Set or tighten the deadline. A dispatcher must call this before
    /// evaluating a callable policy. It never extends an existing deadline.
    pub fn set_timeout(&self, timeout: Duration) -> Result<(), RuntimeError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed("on-demand deadline is out of range".into())
        })?;
        let mut state = self.state()?;
        state.deadline = Some(state.deadline.map_or(deadline, |old| old.min(deadline)));
        Self::check_live(&state)
    }

    pub fn requires_caller_thread(&self) -> bool {
        self.0.runtime.annotation_callbacks_require_caller_thread()
    }

    pub fn fail(&self, detail: impl Into<String>) -> RuntimeError {
        let error = RuntimeError::PolicyInvocationFailed(detail.into());
        match self.state() {
            Ok(mut state) => {
                let first = state.failure.get_or_insert(error);
                first.clone()
            }
            Err(error) => error,
        }
    }

    pub(crate) fn before_dispatch(&self, name: &str) -> Result<(), RuntimeError> {
        let mut state = self.state()?;
        Self::check_live(&state)?;
        let report = state.reports.get_mut(name).ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed("missing annotation resolution report".into())
        })?;
        report.provider_calls += 1;
        Ok(())
    }

    /// False never resolves input paths, dependencies, or providers. True
    /// resolves the fixed binding input once and reuses its validated result.
    pub fn annotate(&self, name: &str, required: bool) -> Result<JsonValue, RuntimeError> {
        self.annotate_inner(name, required)
            .map_err(|error| self.fail(error.to_string()))
    }

    fn annotate_inner(&self, name: &str, required: bool) -> Result<JsonValue, RuntimeError> {
        {
            let mut state = self.state()?;
            Self::check_live(&state)?;
            let report = state.reports.get_mut(name).ok_or_else(|| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "annotation '{name}' is not bound on demand at this intervention point"
                ))
            })?;
            if !required {
                report.skipped_calls = report.skipped_calls.saturating_add(1);
                if report.status == "unrequested" {
                    report.status = "skipped";
                }
                return Ok(json!({"status": "not_required"}));
            }
            if state.resolving {
                return Err(RuntimeError::PolicyInvocationFailed(
                    "recursive on-demand annotation resolution is forbidden".into(),
                ));
            }
            if let Some(value) = state.values.get(name).cloned() {
                if let Some(report) = state.reports.get_mut(name) {
                    report.cache_hits = report.cache_hits.saturating_add(1);
                }
                return Ok(json!({"status": "completed", "value": value}));
            }
        }

        let manifest = self.0.runtime.manifest();
        let config = manifest
            .intervention_points
            .get(&self.0.point)
            .ok_or_else(|| RuntimeError::ManifestInvalid("missing intervention point".into()))?;
        let mut needed = BTreeSet::new();
        let mut pending = vec![name.to_string()];
        while let Some(next) = pending.pop() {
            if !needed.insert(next.clone()) {
                continue;
            }
            let binding = config.annotations.get(&next).ok_or_else(|| {
                RuntimeError::ManifestInvalid(format!("missing annotation '{next}'"))
            })?;
            pending.extend(
                manifest
                    .annotation_dependencies(binding)?
                    .into_iter()
                    .map(str::to_string),
            );
        }
        for next in self.0.runtime.annotation_order(self.0.point)? {
            if !needed.contains(&next) {
                continue;
            }
            let completed = {
                let mut state = self.state()?;
                Self::check_live(&state)?;
                if state.values.contains_key(&next) {
                    continue;
                }
                if state.resolving {
                    return Err(RuntimeError::PolicyInvocationFailed(
                        "concurrent resolution within one evaluation is forbidden".into(),
                    ));
                }
                state.resolving = true;
                if let Some(report) = state.reports.get_mut(&next) {
                    report.status = "in_progress";
                }
                state.values.clone()
            };
            let output = self.0.runtime.dispatch_demanded_annotation(
                self.0.point,
                &next,
                &self.0.input,
                &completed,
                self,
            );
            let mut state = self.state()?;
            state.resolving = false;
            let output = Self::check_live(&state).and(output);
            match output {
                Ok(value) => {
                    state.values.insert(next.clone(), value);
                    if let Some(report) = state.reports.get_mut(&next) {
                        report.status = "completed";
                    }
                }
                Err(error) => {
                    if let Some(report) = state.reports.get_mut(&next) {
                        report.status = "failed";
                        report.failure_reason = Some(error.reason().to_string());
                    }
                    state.failure.get_or_insert(error.clone());
                    return Err(error);
                }
            }
        }
        let state = self.state()?;
        Self::check_live(&state)?;
        let value = state.values.get(name).ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed("annotation resolution produced no value".into())
        })?;
        Ok(json!({"status": "completed", "value": value}))
    }

    pub(crate) fn finish(
        &self,
    ) -> Result<(BTreeMap<String, AnnotationResolution>, Option<RuntimeError>), RuntimeError> {
        let mut state = self.state()?;
        if let Err(error) = Self::check_live(&state) {
            state.failure.get_or_insert(error);
        }
        state.closed = true;
        let failure_reason = state
            .failure
            .as_ref()
            .map(|error| error.reason().to_string());
        for report in state.reports.values_mut() {
            if report.status == "in_progress" {
                report.status = "failed";
                report.failure_reason = failure_reason.clone();
            }
        }
        Ok((state.reports.clone(), state.failure.clone()))
    }
}
