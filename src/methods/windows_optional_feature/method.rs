use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for WindowsOptionalFeature {
    fn execute(&self) -> R<()> {
        trace!("Executing windows optional feature: {}", self.name);
        set_optional_feature_state(self)
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!(
            "Retrieving current value for windows optional feature: {}",
            self.name
        );
        Ok(get_optional_feature_state(self.name.clone())?.to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "windows_optional_feature".to_string(),
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
        Ok(Self {
            name: raw.target,
            action: serde_plain::from_str(&raw.action)
                .map_err(|e| format!("Failed to deserialize action: {}", e))?,
        })
    }
}
