use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone)]
pub struct WindowsCapability {
    pub name: String,
    pub action: Action,
}


#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Present,
    NotPresent,
}