use std::path::PathBuf;

use csv::Reader;

use super::*;
use crate::{methods::FROM_RAW_REGISTRY, traits::*};

pub fn parse_csv(file_path: PathBuf) -> R<Vec<Rule>> {
    let mut rdr = Reader::from_path(file_path)?;
    let mut rules: Vec<Rule> = Vec::new();

    // init a list of all methods string names
    let methods: Vec<&'static str> = FROM_RAW_REGISTRY.keys().copied().collect();

    for result in rdr.deserialize() {
        let record: CsvRecord = result?;

        let raw_method = record.to_raw();

        if let Some(from_raw) = FROM_RAW_REGISTRY.get(raw_method.method.as_str()) {
            let method = from_raw(&raw_method);
            let rule = Rule {
                id: record.id.clone(),
                name: record.name.clone(),
                category: record.category.clone(),
                method,
                tags: record
                    .tags
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
            };
            rules.push(rule);
        } else {
            warn!(
                "Invalid method '{}' in record '{}'.",
                record.method, record.id
            );
            if let Some(suggestion) = methods
                .iter()
                .min_by_key(|m| strsim::levenshtein(m, &record.method))
            {
                eprintln!("Did you mean '{}'?", suggestion);
            }
            return Err(format!(
                "Invalid method '{}' in record '{}'.",
                record.method, record.id
            )
            .into());
        }
    }
    Ok(rules)
}
