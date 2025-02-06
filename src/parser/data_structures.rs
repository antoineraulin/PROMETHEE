use serde::{Deserialize, Serialize};

use crate::methods::RawMethod;

#[derive(Debug, Serialize, Deserialize)]
pub struct CsvRecord {
    pub id: String,
    pub name: String,
    pub category: String,
    pub method: String,
    pub target: String,
    pub option1: String,
    pub option2: String,
    pub scope: String,
    pub action: String,
    pub tags: String,
}

impl CsvRecord {
    pub fn to_raw(&self) -> RawMethod {
        RawMethod {
            method: self.method.clone(),
            target: self.target.clone(),
            option1: self.option1.clone(),
            option2: self.option2.clone(),
            scope: self.scope.clone(),
            action: self.action.clone(),
        }
    }
}
