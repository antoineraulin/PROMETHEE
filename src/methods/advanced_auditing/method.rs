use std::sync::Mutex;

use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for AdvancedAuditing {
    fn execute(&self) -> R<()> {
        trace!("Executing AdvancedAuditing rule for GUID: {}", self.guid);
        let mut strategies = AUDIT_STRATEGIES
            .get_or_init(|| Mutex::new(init_audit_strategies().unwrap_or_default()))
            .lock()
            .map_err(|_| "Failed to lock audit strategies")?;

        let s_guid_lc = self.guid.to_lowercase();

        if let Some(strategy) = strategies
            .iter_mut()
            .find(|s| s.guid.to_lowercase() == s_guid_lc)
        {
            strategy.inclusion_parameter = Some(self.value);
            strategy.parameter_value = if self.value as i8 == -1 {
                Some(0)
            } else {
                Some(self.value as i8)
            };
            debug!("Updated strategy: {:?}", strategy);
            Ok(())
        } else {
            error!("Audit strategy with GUID {} not found", s_guid_lc);
            Err(format!("Audit strategy with GUID {} not found, ensure the audit guid is present in audit.csv and the latest admx for the windows version are installed", s_guid_lc).into())
        }
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!(
            "Getting current value for AdvancedAuditing rule with GUID: {}",
            self.guid
        );
        let strategies = AUDIT_STRATEGIES
            .get_or_init(|| Mutex::new(init_audit_strategies().unwrap_or_default()))
            .lock()
            .map_err(|_| "Failed to lock audit strategies")?;

        let s_guid_lc = self.guid.to_lowercase();

        let strategy = strategies
            .iter()
            .find(|s| s.guid.to_lowercase() == s_guid_lc);

        match strategy {
            None => {
                warn!("Audit strategy not found, defaulting to Disabled");
                Ok(AdvancedAuditing {
                    guid: s_guid_lc,
                    value: AuditParameter::Disabled,
                }
                .to_raw(false))
            }
            Some(strategy) => Ok(AdvancedAuditing {
                guid: strategy.guid.clone(),
                value: strategy
                    .inclusion_parameter
                    .unwrap_or(AuditParameter::Disabled),
            }
            .to_raw(false)),
        }
    }

    fn to_raw(&self, compare_mode: bool) -> RawMethod {
        let target = if compare_mode {
            self.guid.clone().to_lowercase()
        } else {
            self.guid.clone()
        };
        RawMethod {
            method: "advanced_auditing".to_string(),
            target,
            option1: "".to_string(),
            option2: "".to_string(),
            scope: "".to_string(),
            action: serde_plain::to_string(&self.value).unwrap(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self> {
        Ok(AdvancedAuditing {
            guid: raw.target.clone().to_lowercase(),
            value: serde_plain::from_str(&raw.action)
                .map_err(|e| format!("Failed to deserialize action: {}", e))?,
        })
    }
}
