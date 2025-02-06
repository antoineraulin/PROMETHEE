use log::{debug, trace};

use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

use super::data_structures::LocalGroupPolicyObject;

impl RuleTrait for LocalGroupPolicyObject {
    fn execute(&self) -> R<()> {
        trace!(
            "Executing LGPO rule with registry key: {}, value_name: {}, scope: {:?}",
            self.registry_key,
            self.value_name,
            self.configuration
        );
        let mut lgpos = get_lgpos().map_err(|_| "Failed to lock LGPOs")?;

        if let Some(existing_lgpo) = lgpos.iter_mut().find(|lgpo| {
            lgpo.registry_key.to_lowercase() == self.registry_key.to_lowercase()
                && lgpo.value_name.to_lowercase() == self.value_name.to_lowercase()
                && lgpo.configuration == self.configuration
        }) {
            *existing_lgpo = self.clone();
        } else {
            lgpos.push(self.clone());
        }
        Ok(())
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!(
            "Getting current value for LGPO rule with registry key: {} and value_name: {}",
            self.registry_key,
            self.value_name
        );
        let lgpos = get_lgpos().map_err(|_| "Failed to lock LGPOs")?;

        let lgpo = lgpos.iter().find(|lgpo| {
            lgpo.registry_key.to_lowercase() == self.registry_key.to_lowercase()
                && lgpo.value_name.to_lowercase() == self.value_name.to_lowercase()
                && lgpo.configuration == self.configuration
        });

        let lgpo = match lgpo {
            Some(lgpo) => lgpo,
            None => &{
                warn!("LGPO not found: {:?}", self);
                warn!("Defaulting to delete action");
                let mut lgpo = self.clone();
                lgpo.action = Action::Delete;
                lgpo
            },
        };

        debug!("Found LGPO: {:?}", lgpo);
        Ok(lgpo.to_raw(false))
    }

    fn to_raw(&self, compare_mode: bool) -> RawMethod {
        let target = if compare_mode {
            self.registry_key.clone().to_lowercase()
        } else {
            self.registry_key.clone()
        };
        let option1 = if compare_mode {
            self.value_name.clone().to_lowercase()
        } else {
            self.value_name.clone()
        };
        RawMethod {
            method: "lgpo".to_string(),
            target,
            action: serde_plain::to_string(&self.action)
                .map_err(|e| format!("Failed to serialize action: {}", e))
                .unwrap(),
            option1,
            option2: "".to_string(),
            scope: serde_plain::to_string(&self.configuration)
                .map_err(|e| format!("Failed to serialize configuration: {}", e))
                .unwrap(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let configuration = serde_plain::from_str(&raw.scope)
            .map_err(|e| format!("Invalid configuration : {}", e))?;
        let action =
            serde_plain::from_str(&raw.action).map_err(|e| format!("Invalid action : {}", e))?;
        Ok(LocalGroupPolicyObject {
            configuration,
            action,
            registry_key: raw.target,
            value_name: raw.option1,
        })
    }
}
