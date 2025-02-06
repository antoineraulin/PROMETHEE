use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for SecEdit {
    fn execute(&self) -> R<()> {
        trace!("Executing SecEdit rule for field: {}", self.field);
        set_secedit_field(self)
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!("Retrieving current value for field: {}", self.field);
        Ok(get_secedit(self)?.to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        let scope_value = serde_plain::to_string(&self.scope_value)
            .map_err(|e| error!("Failed to serialize SecEdit scope_value: {}", e))
            .unwrap();
        let (scope, value) = scope_value
            .split_once(':')
            .unwrap_or((scope_value.as_str(), ""));
        RawMethod {
            method: "secedit".to_string(),
            target: self.field.clone(),
            option1: "".to_string(),
            option2: "".to_string(),
            scope: scope.to_string(),
            action: value.to_string(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let scope_value = format!("{}:{}", raw.scope, raw.action);
        Ok(Self {
            field: raw.target,
            scope_value: serde_plain::from_str(&scope_value)
                .map_err(|e| format!("Failed to parse SecEdit scope_value: {}", e))?,
        })
    }
}
