use super::utils::*;
use super::*;
use crate::{methods::*, traits::*};
use std::path::PathBuf;

impl RuleTrait for SoftwareRestrictionPolicy {
    fn execute(&self) -> R<()> {
        trace!(
            "Executing SoftwareRestrictionPolicy rule for target: {:?}",
            self.target
        );
        // We check if the rule exists, then insert or replace it
        let existing = match self.current_value() {
            Ok(existing) => Some(existing),
            Err(_) => None,
        };
        debug!("Existing rule: {:?}", existing);
        let mut rules = get_global_state()?;
        if let Some(existing_rule) = existing {
            let state: State = serde_plain::from_str(&existing_rule.action)
                .map_err(|e| format!("SAFER : Invalid state '{}': {}", existing_rule.action, e))?;
            if state == State::NotExists {
                debug!("Creating new rule");
                rules.push(self.clone());
            } else if let Some(index) = rules.iter().position(|r| r.target == self.target) {
                debug!("Updating existing rule");
                rules[index] = self.clone();
            } else {
                debug!("Already exists");
            }
        } else {
            debug!("Creating new rule");
            rules.push(self.clone());
        }
        Ok(())
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!(
            "Getting current value for SoftwareRestrictionPolicy rule with target: {:?}",
            self.target
        );
        let current_rules = get_global_state()?.to_owned();
        debug!("Current rules: {:?}", current_rules);
        let rule = current_rules
            .iter()
            .find(|rule| rule.target == self.target)
            .cloned();

        match rule {
            Some(rule) => Ok(rule.to_raw(false)),
            None => {
                warn!("Equivalent rule not found");
                let mut new_rule = self.clone();
                new_rule.state = State::NotExists;
                Ok(new_rule.to_raw(false))
            }
        }
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        let prefix = format!("[{}] ", env!("CARGO_CRATE_NAME").to_lowercase());
        RawMethod {
            method: "safer".to_string(),
            target: match &self.target {
                Target::Path(p) => p.to_string_lossy().into_owned(),
                Target::UrlZone(z) => serde_plain::to_string(z).unwrap(),
            },
            action: serde_plain::to_string(&self.state).unwrap(),
            option1: serde_plain::to_string(&self.security_level).unwrap(),
            option2: self
                .description
                .clone()
                .map(|desc| {
                    if desc.starts_with(prefix.as_str()) {
                        desc.replacen(prefix.as_str(), "", 1)
                    } else {
                        desc
                    }
                })
                .unwrap_or_default(),
            scope: serde_plain::to_string(&self.rule_type).unwrap(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let rule_type = serde_plain::from_str::<RuleType>(&raw.scope)
            .map_err(|e| format!("Invalid rule type '{}': {}", raw.scope, e))?;

        let target = match rule_type {
            RuleType::Paths => Target::Path(
                serde_plain::from_str::<PathBuf>(&raw.target)
                    .map_err(|e| format!("Invalid path '{}': {}", raw.target, e))?,
            ),
            RuleType::UrlZones => Target::UrlZone(
                serde_plain::from_str::<UrlZones>(&raw.target)
                    .map_err(|e| format!("Invalid URL zone '{}': {}", raw.target, e))?,
            ),
            RuleType::Hashes => unimplemented!(),
        };

        let state = serde_plain::from_str::<State>(&raw.action)
            .map_err(|e| format!("Invalid state '{}': {}", raw.action, e))?;

        let security_level = serde_plain::from_str::<SecurityLevel>(&raw.option1)
            .map_err(|e| format!("Invalid security level '{}': {}", raw.option1, e))?;

        let description = if raw.option2.is_empty() {
            None
        } else {
            Some(raw.option2.clone())
        };

        Ok(Self {
            target,
            security_level,
            rule_type,
            description,
            last_modified: None,
            lgpo_guid: None,
            state,
        })
    }
}
