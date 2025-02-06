use super::*;
use crate::secedit::utils::get_global_secedit;
use crate::traits::*;
use crate::utils::read_registry;
use std::collections::HashMap;
use winsafe::prelude::advapi_Hkey;
use winsafe::{RegistryValue, HKEY};

/// Retrieves the current action associated with a service.
///
/// Attempts to get the start value from the SecEdit configuration.
/// If not found, reads the start value directly from the registry.
///
/// # Arguments
///
/// * `service_name` - The name of the service.
///
/// # Returns
///
/// * `R<Action>` - The action corresponding to the service's start value.
pub fn get_service_current_action(service_name: &str) -> R<Action> {
    debug!("Getting current action for service: {}", service_name);
    // Try to get the start value from SecEdit config
    if let Ok(start_value) = get_start_value_from_secedit(service_name) {
        debug!("Start value from SecEdit: {}", start_value);
        return map_start_value_to_action(start_value, service_name);
    }
    // If not found, read from registry directly
    warn!("Start value not found in SecEdit config; reading from registry");
    let start_value = read_registry_dword(
        &format!(r#"System\CurrentControlSet\Services\{}"#, service_name),
        "Start",
    )?;
    map_start_value_to_action(start_value, service_name)
}

/// Retrieves the service's start value from the SecEdit configuration.
///
/// This function accesses the globally stored SecEdit configuration,
/// which holds security settings applied to the system.
///
/// # Arguments
///
/// * `service_name` - The name of the service.
///
/// # Returns
///
/// * `R<u32>` - The start value as a 32-bit unsigned integer.
fn get_start_value_from_secedit(service_name: &str) -> R<u32> {
    debug!(
        "Retrieving start value from SecEdit for service: {}",
        service_name
    );
    let config = get_global_secedit().map_err(|_| "Failed to lock SecEdit configuration")?;

    if let Some(registry_values) = config.get("Registry Values") {
        let key = format!(
            r#"MACHINE\System\CurrentControlSet\Services\{}\Start"#,
            service_name
        );
        if let Some(value) = registry_values.get(&key) {
            debug!("Found start value in SecEdit config: {}", value);
            // Parse the DWORD value from the SecEdit entry
            let start_value = parse_secedit_dword(value)?;
            return Ok(start_value);
        }
    }
    Err("Start value not found in SecEdit config".into())
}

/// Parses a SecEdit DWORD string value into a 32-bit unsigned integer.
///
/// The SecEdit DWORD value is typically in the format "4,X", where X is the value and 4 the marker for a DWORD.
///
/// # Arguments
///
/// * `value` - The string representation of the DWORD value.
///
/// # Returns
///
/// * `R<u32>` - The parsed DWORD value.
fn parse_secedit_dword(value: &str) -> R<u32> {
    debug!("Parsing SecEdit DWORD value: {}", value);
    // Split the value by comma and parse the first part
    let parts: Vec<&str> = value.split(',').collect();
    if let Some(second_part) = parts.get(1) {
        second_part
            .parse::<u32>()
            .map_err(|_| "Invalid DWORD format".into())
    } else {
        Err("Empty value".into())
    }
}

/// Maps the service's start value to the corresponding `Action` enum variant.
///
/// This function translates the numerical start values to meaningful actions.
///
/// # Arguments
///
/// * `start_value` - The service's start value.
/// * `service_name` - The name of the service.
///
/// # Returns
///
/// * `R<Action>` - The action corresponding to the start value.
fn map_start_value_to_action(start_value: u32, service_name: &str) -> R<Action> {
    debug!(
        "Mapping start value {} to action for service {}",
        start_value, service_name
    );
    match start_value {
        0 => Ok(Action::Boot),
        1 => Ok(Action::System),
        2 => Ok(Action::Automatic),
        3 => Ok(Action::Manual),
        4 => Ok(Action::Disabled),
        _ => {
            warn!(
                "Invalid start value for service {}: {}",
                service_name, start_value
            );
            Err(format!(
                "Invalid start value for service {}: {}",
                service_name, start_value
            )
            .into())
        }
    }
}

/// Reads a DWORD value from the registry.
///
/// Accesses the Windows registry to retrieve a DWORD value for the given key and name.
///
/// # Arguments
///
/// * `key` - The registry key path.
/// * `name` - The name of the registry value.
///
/// # Returns
///
/// * [R]<[u32]> - The DWORD value retrieved from the registry.
fn read_registry_dword(key: &str, name: &str) -> R<u32> {
    debug!(
        "Reading registry DWORD value from key: {}, name: {}",
        key, name
    );
    let value = read_registry(HKEY::LOCAL_MACHINE, key, name);
    match value {
        Ok(v) => match v {
            RegistryValue::Dword(n) => {
                debug!("Retrieved DWORD value: {}", n);
                Ok(n)
            }
            _ => {
                warn!("Invalid registry value type for {}: {:?}", key, v);
                warn!("Considering service is non-existent or disabled");
                Ok(4)
            }
        },
        Err(e) => {
            warn!("Failed to read registry value: {}", e);
            warn!("Considering service is non-existent or disabled");
            Ok(4)
        }
    }
}

/// Sets the action for a given service by updating the SecEdit configuration.
///
/// This function modifies the global SecEdit configuration to change the service's start value,
/// which determines how the service should be managed by the system.
///
/// # Arguments
///
/// * `service` - A reference to the `Service` struct containing service details.
///
/// # Returns
///
/// * `R<()>` - Returns `Ok(())` if the action was set successfully, or an error otherwise.
pub fn set_service_action(service: &Service) -> R<()> {
    debug!("Setting action for service: {}", service.name);
    let start_value = service.action.clone() as u32;

    // Retrieve the SecEdit configuration
    debug!("Retrieving SecEdit configuration");
    let mut config = get_global_secedit().map_err(|_| "Failed to lock SecEdit configuration")?;

    // Ensure 'Registry Values' section exists in the configuration
    let registry_values = config
        .entry("Registry Values".to_string())
        .or_insert_with(HashMap::new);

    // Construct the registry key path for the service's Start value
    let key = format!(
        r#"MACHINE\System\CurrentControlSet\Services\{}\Start"#,
        service.name
    );
    trace!("Registry key for service start value: {}", key);

    // Prepare the value in the format expected by SecEdit (e.g., "4,2")
    let value_str = format!("4,{}", start_value);
    trace!("Setting start value in SecEdit config: {}", value_str);

    // Insert or update the registry value in the SecEdit configuration
    registry_values.insert(key, value_str);
    debug!("Service action updated in SecEdit configuration");

    Ok(())
}
