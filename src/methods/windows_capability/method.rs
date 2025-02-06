use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for WindowsCapability {
    fn execute(&self) -> R<()> {
        trace!("Executing windows capability: {}", self.name);
        set_capability_state(self)
    }

    fn current_value(&self) -> R<RawMethod>
    where
        Self: Sized,
    {
        trace!(
            "Retrieving current value for windows capability: {}",
            self.name
        );
        Ok(get_capability_state(self.name.clone())?.to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "windows_capability".to_string(),
            target: self.name.clone(),
            option1: "".to_string(),
            option2: "".to_string(),
            scope: "".to_string(),
            action: serde_plain::to_string(&self.action).unwrap(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let action: Action = serde_plain::from_str(&raw.action)
            .map_err(|e| format!("Failed to deserialize action: {}", e))?;
        Ok(WindowsCapability {
            name: raw.target,
            action,
        })
    }
}
