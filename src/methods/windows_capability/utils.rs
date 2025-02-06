use convert_case::{Case, Casing};
use super::*;
use crate::traits::*;
use std::process::Command;

/// Retrieves the current state of a Windows capability using PowerShell.
///
/// # Arguments
/// * `name` - The name of the capability to query
///
/// # Returns
/// A `WindowsCapability` with the retrieved state, or an error if the command or parsing fails
pub fn get_capability_state(name: String) -> R<WindowsCapability> {
    debug!("Requesting current state for capability: {}", name);
    // We use PowerShell here to leverage the DISM module which allows us to query capabilities directly.
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "(Get-WindowsCapability -LimitAccess -Online -Name '{}').State",
                name
            ),
        ])
        .output()?;

    trace!("Raw PowerShell output: {:?}", output);
    let action = serde_plain::from_str::<Action>(&String::from_utf8_lossy(&output.stdout).trim().to_case(Case::Snake))?;
    debug!("Parsed capability action: {:?}", action);
    Ok(WindowsCapability { name, action })
}

/// Sets the specified WindowsCapability to the desired state using PowerShell.
///
/// # Arguments
/// * `capability` - The `WindowsCapability` struct containing the name and desired action
///
/// # Returns
/// An empty Ok if successful, or an error if the command fails or returns an error message
pub fn set_capability_state(capability: &WindowsCapability) -> R<()> {
    debug!("Applying new state for capability: {}", capability.name);
    // We match on the action enum to decide if we should add or remove the capability, as required by PowerShell.
    let action_str = match capability.action {
        Action::Present => "Add",
        Action::NotPresent => "Remove",
    };

    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "{}-WindowsCapability -Online -Name '{}' {}",
                action_str,
                capability.name,
                if action_str == "Add" {
                    "-LimitAccess"
                } else {
                    ""
                }
            ),
        ])
        .output()?;

    trace!("PowerShell command executed, output: {:?}", output);
    if !output.stderr.is_empty() {
        return Err("Failed to set capability state.".into());
    }

    Ok(())
}
