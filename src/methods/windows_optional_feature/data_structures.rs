use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct WindowsOptionalFeature {
    pub name: String,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Enable,
    Disable,
}
