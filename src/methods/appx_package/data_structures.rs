use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct AppxPackage {
    pub name: String,
    pub action: Action,
    pub package_source: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Install,
    Stage,
    Remove,
}
