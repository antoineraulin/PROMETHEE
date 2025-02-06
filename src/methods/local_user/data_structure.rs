use super::utils::*;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct LocalAccount {
    pub id: String,
    pub groups: Vec<String>,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Enabled,
    Disabled,
    NotExist,
}

pub enum IdType {
    Username,
    SID,
    RID,
}

pub static COMPUTER_SID: LazyLock<String> = LazyLock::new(|| get_computer_sid().unwrap());
