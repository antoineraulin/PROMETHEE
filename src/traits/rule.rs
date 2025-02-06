use std::fmt::Debug;

use crate::{
    methods::{method::*, FROM_RAW_REGISTRY},
    parser::CsvRecord,
};

pub type R<T> = Result<T, Box<dyn std::error::Error>>;

pub trait RuleTrait: Debug {
    fn execute(&self) -> R<()>;
    fn current_value(&self) -> R<RawMethod>;
    fn to_raw(&self, compare_mode: bool) -> RawMethod;
    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub method: Box<dyn RuleTrait>,
    pub tags: Vec<String>,
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.name == other.name
            && self.category == other.category
            && self.tags == other.tags
            && self.method.to_raw(true) == other.method.to_raw(true)
    }
}

impl Rule {
    pub fn to_csv(&self) -> CsvRecord {
        let raw_method = self.method.to_raw(false);
        CsvRecord {
            id: self.id.clone(),
            name: self.name.clone(),
            category: self.category.clone(),
            method: raw_method.method,
            target: raw_method.target,
            option1: raw_method.option1,
            option2: raw_method.option2,
            scope: raw_method.scope,
            action: raw_method.action,
            tags: self.tags.join(","),
        }
    }

    pub fn backup(&self) -> R<Self> {
        let raw_method = self.method.current_value()?;
        if let Some(from_raw) = FROM_RAW_REGISTRY.get(raw_method.method.as_str()) {
            let method = from_raw(&raw_method);
            Ok(Self {
                id: self.id.clone(),
                name: self.name.clone(),
                category: self.category.clone(),
                method,
                tags: self.tags.clone(),
            })
        } else {
            Err(format!("Invalid method '{}'", raw_method.method).into())
        }
    }

    pub fn pretty_display(&self) -> String {
        format!("{} {}", self.id, self.name,)
    }

    pub fn pretty_diff(r1: &Rule, r2: &Rule) -> String {
        let mut diffs = vec![];

        if r1.id != r2.id {
            diffs.push(format!("id: expected {} found {}", r1.id, r2.id));
        }
        if r1.name != r2.name {
            diffs.push(format!("name: expected {} found {}", r1.name, r2.name));
        }
        if r1.category != r2.category {
            diffs.push(format!(
                "category: expected {} found {}",
                r1.category, r2.category
            ));
        }

        let raw1 = r1.method.to_raw(true);
        let raw2 = r2.method.to_raw(true);
        if raw1.method != raw2.method {
            diffs.push(format!(
                "method: expected {} found {}",
                raw1.method, raw2.method
            ));
        }
        if raw1.target != raw2.target {
            diffs.push(format!(
                "target: expected {} found {}",
                raw1.target, raw2.target
            ));
        }
        if raw1.option1 != raw2.option1 {
            diffs.push(format!(
                "option1: expected {} found {}",
                raw1.option1, raw2.option1
            ));
        }
        if raw1.option2 != raw2.option2 {
            diffs.push(format!(
                "option2: expected {} found {}",
                raw1.option2, raw2.option2
            ));
        }
        if raw1.scope != raw2.scope {
            diffs.push(format!(
                "scope: expected {} found {}",
                raw1.scope, raw2.scope
            ));
        }
        if raw1.action != raw2.action {
            diffs.push(format!(
                "action: expected {} found {}",
                raw1.action, raw2.action
            ));
        }

        if r1.tags != r2.tags {
            diffs.push(format!("tags: expected {:?} found {:?}", r1.tags, r2.tags));
        }

        if diffs.is_empty() {
            "No differences".to_string()
        } else {
            diffs.join(", ")
        }
    }
}
