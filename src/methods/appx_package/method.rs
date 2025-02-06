use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for AppxPackage {
    fn execute(&self) -> R<()> {
        trace!("Executing action for AppX package: {}", self.name);
        let current_state = Self::from_raw(self.current_value()?)?;

        match self.action {
            Action::Remove => {
                // Remove the Appx package if installed
                if current_state.action == Action::Install {
                    remove_appx_package(&self.name)?;
                }

                // Remove the provisioned package if staged
                if current_state.action == Action::Stage {
                    remove_provisioned_appx_package(&self.name)?;
                }
            }
            Action::Install => {
                // Install the Appx package if not installed
                if current_state.action != Action::Install {
                    install_appx_package(self)?;
                }
            }
            Action::Stage => {
                // Remove the Appx package if installed
                if current_state.action == Action::Install {
                    remove_appx_package(&self.name)?;
                }

                // Provision the Appx package if not staged
                if current_state.action != Action::Stage {
                    provision_appx_package(self)?;
                }
            }
        }

        Ok(())
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!("Retrieving current state for AppX package: {}", self.name);
        let current_state = get_appx_package(self.name.clone())?;
        Ok(current_state.to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "appx_package".to_string(),
            target: self.name.clone(),
            option1: "".to_string(),
            option2: "".to_string(),
            scope: self.package_source.clone().unwrap_or_default(),
            action: serde_plain::to_string(&self.action).unwrap(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        Ok(AppxPackage {
            name: raw.target,
            action: serde_plain::from_str(&raw.action)
                .map_err(|e| format!("Error deserializing action: {}", e))?,
            package_source: if raw.scope.is_empty() {
                None
            } else {
                Some(raw.scope)
            },
        })
    }
}
