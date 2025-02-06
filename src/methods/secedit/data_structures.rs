use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use crate::methods::lgpo;

pub type SecEditConfig = HashMap<String, HashMap<String, String>>;

pub static SECEDIT_CONFIG: OnceLock<Mutex<SecEditConfig>> = OnceLock::new();

/// Represents a security edit rule that can be applied.
#[derive(Debug)]
pub struct SecEdit {
    /// The field (policy setting) to modify.
    pub field: String,
    /// The scope (section) of the security policy.
    pub scope_value: ScopeValue,
}

/// Enum representing the scope and value of the security policy.
#[derive(Debug, PartialEq, Clone)]
pub enum ScopeValue {
    SystemAccess(String),
    PrivilegeRights(Vec<String>),
    RegistryValues(lgpo::Action),
}
