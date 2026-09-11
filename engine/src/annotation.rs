use crate::{constants::annotation as annotation_key, JsonValue, RuntimeError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotatorType {
    Classifier,
    Llm,
    Endpoint,
}

impl AnnotatorType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classifier => "classifier",
            Self::Llm => "llm",
            Self::Endpoint => "endpoint",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnotatorConfig {
    #[serde(rename = "type")]
    pub annotator_type: AnnotatorType,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnotationConfig {
    pub from: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnnotatorInvocation {
    #[serde(flatten)]
    pub fields: BTreeMap<String, JsonValue>,
}

pub(crate) fn system_prompt_source(
    fields: &BTreeMap<String, JsonValue>,
) -> Result<Option<crate::manifest::PinnedHttpsSource>, RuntimeError> {
    let Some(value) = fields.get("system_prompt_url") else {
        return Ok(None);
    };
    if fields.contains_key("system_prompt") || fields.contains_key("prompt") {
        return Err(RuntimeError::ManifestInvalid(
            "system_prompt_url must not be combined with system_prompt or prompt".to_string(),
        ));
    }
    crate::manifest::PinnedHttpsSource::from_value(value).map(Some)
}

impl AnnotatorInvocation {
    pub fn from_annotation(annotator: &AnnotatorConfig, annotation: &AnnotationConfig) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert(
            annotation_key::TYPE.to_string(),
            JsonValue::String(annotator.annotator_type.as_str().to_string()),
        );
        for (key, value) in &annotator.fields {
            fields.insert(key.clone(), value.clone());
        }
        fields.insert(
            annotation_key::FROM.to_string(),
            JsonValue::String(annotation.from.clone()),
        );
        for (key, value) in &annotation.fields {
            fields.insert(key.clone(), value.clone());
        }
        Self { fields }
    }

    pub fn input_from(&self) -> Option<&str> {
        self.fields
            .get(annotation_key::FROM)
            .or_else(|| self.fields.get(annotation_key::INPUT_FROM))
            .and_then(JsonValue::as_str)
    }

    pub fn field(&self, name: &str) -> Option<&JsonValue> {
        self.fields.get(name)
    }
}

pub trait AnnotatorDispatcher: Send + Sync {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError>;
}
