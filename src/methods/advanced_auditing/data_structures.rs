use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuditStrategy {
    pub computer_name: String,
    pub target: String,
    pub sub_category: String,
    pub guid: String,
    #[serde(deserialize_with = "super::utils::to_audit_parameter")]
    #[serde(serialize_with = "super::utils::from_audit_parameter")]
    pub inclusion_parameter: Option<AuditParameter>,
    #[serde(deserialize_with = "super::utils::to_audit_parameter")]
    #[serde(serialize_with = "super::utils::from_audit_parameter")]
    pub exclusion_parameter: Option<AuditParameter>,
    pub parameter_value: Option<i8>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditParameter {
    Disabled = -1,
    NoAuditing = 0,
    Success = 1,
    Failure = 2,
    SuccessAndFailure = 3,
}

#[derive(Debug)]
pub struct AdvancedAuditing {
    pub guid: String,
    pub value: AuditParameter,
}

pub static AUDIT_STRATEGIES: OnceLock<Mutex<Vec<AuditStrategy>>> = OnceLock::new();