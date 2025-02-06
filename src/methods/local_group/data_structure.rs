use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct LocalGroup {
    pub id: String,
    pub members: Vec<String>,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    NotExist,
    Exist,
}

#[derive(Debug)]
pub enum IdType {
    Name,
    SID,
}
