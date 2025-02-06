use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for Service {
    fn execute(&self) -> R<()> {
        trace!("Executing Service rule for service: {}", self.name);
        set_service_action(self)
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!("Retrieving current value for service: {}", self.name);
        let action = get_service_current_action(&self.name)?;
        Ok(Service {
            name: self.name.clone(),
            action,
        }
        .to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "service".to_string(),
            target: self.name.clone(),
            action: serde_plain::to_string(&self.action).unwrap(),
            option1: "".to_string(),
            option2: "".to_string(),
            scope: "".to_string(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let action: Action = serde_plain::from_str(&raw.action)
            .map_err(|e| format!("Failed to deserialize action: {}", e))?;
        Ok(Service {
            name: raw.target,
            action,
        })
    }
}
