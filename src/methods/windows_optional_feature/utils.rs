use std::process::Command;

use convert_case::{Case, Casing};

use super::*;
use crate::traits::*;

/// Retrieves the current state of a Windows optional feature using PowerShell.
///
/// # Arguments
/// * `name` - The name of the optional feature to query
///
/// # Returns
/// A `WindowsOptionalFeature` with the retrieved state, or an error if the command or parsing fails
pub fn get_optional_feature_state(name: String) -> R<WindowsOptionalFeature> {
    debug!("Requesting current state for feature: {}", name);
    // We use PowerShell here to leverage the DISM module which allows us to query capabilities directly.
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "(Get-WindowsOptionalFeature -Online -FeatureName '{}').State",
                name
            ),
        ])
        .output()?;

    trace!("Raw PowerShell output: {:?}", output);
    let action_str = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_lowercase();

    let action = match action_str.as_str() {
        "enabled" => Action::Enable,
        "disabled" => Action::Disable,
        _ => {
            warn!("Unknown feature state: {}", action_str);
            warn!("Defaulting to disabled");
            Action::Disable
        }
    };
    debug!("Parsed feature action: {:?}", action);
    Ok(WindowsOptionalFeature { name, action })
}

/// Sets the specified WindowsOptionalFeature to the desired state using PowerShell.
///
/// # Arguments
/// * `feature` - The `WindowsOptionalFeature` struct containing the name and desired action
///
/// # Returns
/// An empty Ok if successful, or an error if the command fails or returns an error message
pub fn set_optional_feature_state(feature: &WindowsOptionalFeature) -> R<()> {
    debug!("Applying new state for optional feature: {}", feature.name);

    let command_prefix = serde_plain::to_string(&feature.action)?.to_case(Case::Pascal);

    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "{}-WindowsOptionalFeature -Online -FeatureName '{}' -NoRestart",
                command_prefix, feature.name,
            ),
        ])
        .output()?;

    trace!("PowerShell command executed, output: {:?}", output);
    if !output.stderr.is_empty() {
        return Err("Failed to set capability state.".into());
    }

    Ok(())
}
