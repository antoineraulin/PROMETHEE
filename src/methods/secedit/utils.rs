use super::*;
use crate::{
    lgpo::{
        utils::{lgpo_export, lgpo_import},
        LGPOCommandArgs, LGPOCommands,
    },
    methods::lgpo,
    traits::*,
    utils::{read_file_as_utf16_utf8, write_to_utf16},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{LockResult, Mutex, MutexGuard},
};

/// # About
/// Retrieves or initializes the global SecEdit configuration as a thread-safe resource.
/// # Returns
/// A locked reference to the configuration, ensuring concurrent safety.
/// # Errors
/// Returns an error if the global lock cannot be acquired.
pub fn get_global_secedit(
) -> LockResult<MutexGuard<'static, HashMap<String, HashMap<String, String>>>> {
    trace!("Entering get_global_secedit to retrieve or initialize the SecEdit config");
    // We lock the global configuration to ensure thread-safety while reading or modifying it
    SECEDIT_CONFIG
        .get_or_init(|| {
            debug!("Initializing SecEdit configuration");
            Mutex::new(get_secedit_config().unwrap_or_default())
        })
        .lock()
}

/// # About
/// Updates the specified field in the given SecEdit configuration.
/// # Arguments
/// * `secedit` - The struct containing the field name, its new value, and scope.
pub fn set_secedit_field(secedit: &SecEdit) -> R<()> {
    trace!("Entering set_secedit_field for field: {}", secedit.field);
    let mut config = get_global_secedit().map_err(|_| "Failed to lock SecEdit configuration")?;

    // Determine the appropriate section based on scope.
    let (scope, value) = match &secedit.scope_value {
        ScopeValue::SystemAccess(str) => ("System Access", str),
        ScopeValue::PrivilegeRights(ids) => ("Privilege Rights", &ids.join(",")),
        ScopeValue::RegistryValues(action) => {
            ("Registry Values", &registry_action_to_value(action)?)
        }
    };

    if let Some(section) = config.get_mut(scope) {
        if value == "-NODATA-" {
            section.remove(&secedit.field);
            debug!(
                "Removed '{}' from '{}' as its value is '-NODATA-'",
                secedit.field, scope
            );
            Ok(())
        } else {
            // Update the configuration with the new value.
            section.insert(secedit.field.clone(), value.clone());
            debug!(
                "Updated '{}' in '{}' with value: '{}'",
                secedit.field, scope, value
            );
            Ok(())
        }
    } else {
        // Warn if the section is not found.
        warn!(
            "Section '{}' not found when updating field '{}'",
            scope, secedit.field
        );
        Err(format!("Section '{}' not found", scope).into())
    }
}

/// # About
/// Retrieves the current value for a specific SecEdit field from configuration.
/// # Arguments
/// * `secedit` - The struct containing the target field name and scope.
/// # Errors
/// Returns an error if the lock is unavailable or the requested field is not found.
pub fn get_secedit(secedit: &SecEdit) -> R<SecEdit> {
    trace!("Entering get_secedit for field: {}", secedit.field);
    let config = get_global_secedit().map_err(|_| "Failed to lock SecEdit configuration")?;

    let section = match secedit.scope_value {
        ScopeValue::SystemAccess(_) => "System Access",
        ScopeValue::PrivilegeRights(_) => "Privilege Rights",
        ScopeValue::RegistryValues(_) => "Registry Values",
    };

    let value = match config.get(section).and_then(|s| s.get(&secedit.field)) {
        Some(value) => value,
        None => &{
            // Warn if the field is not found in the section.
            warn!(
                "Field '{}' not found in section '{}'",
                secedit.field, section
            );
            "-NODATA-".to_string()
        },
    };

    debug!("Found field: {} with value: {}", secedit.field, value);

    let scope_value = match secedit.scope_value {
        ScopeValue::SystemAccess(_) => ScopeValue::SystemAccess(value.clone()),
        ScopeValue::PrivilegeRights(_) => {
            let ids = value.split(',').map(|id| id.to_string()).collect();
            ScopeValue::PrivilegeRights(ids)
        }
        ScopeValue::RegistryValues(_) => {
            let action = value_to_registry_action(value)?;
            ScopeValue::RegistryValues(action)
        }
    };
    Ok(SecEdit {
        field: secedit.field.clone(),
        scope_value,
    })
}

pub fn value_to_registry_action(value: &str) -> R<lgpo::Action> {
    let trimmed = value.trim();
    let (action_type, value) = if trimmed == "-NODATA-" {
        ("-NODATA-", "")
    } else {
        trimmed
            .split_once(',')
            .ok_or_else(|| format!("Invalid registry action format: {}", value))?
    };

    match action_type {
        "1" => {
            let stripped = value.trim_matches('"');
            Ok(lgpo::Action::Sz(stripped.to_string()))
        }
        "3" => {
            let num = value
                .parse::<u32>()
                .map_err(|e| format!("Failed to parse int for binary conversion: {}", e))?;
            let binary_vec = num.to_le_bytes().to_vec();
            Ok(lgpo::Action::Binary(binary_vec))
        }
        "4" => {
            let num = value
                .parse::<u64>()
                .map_err(|e| format!("Failed to parse dword value: {}", e))?;
            Ok(lgpo::Action::Dword(num))
        }
        "7" => {
            let mut values = Vec::new();
            let mut current = String::new();
            let mut in_quotes = false;
            let mut chars = value.chars().peekable();
            
            while let Some(ch) = chars.next() {
                match ch {
                    '"' => {
                        if in_quotes && chars.peek() == Some(&'"') {
                            // Escaped quote
                            chars.next();
                            current.push('"');
                        } else {
                            in_quotes = !in_quotes;
                        }
                    }
                    ',' if !in_quotes => {
                        // Handle special case for empty lines (" ")
                        let trimmed_current = current.trim();
                        if trimmed_current == " " {
                            values.push(String::new());
                        } else {
                            values.push(current);
                        }
                        current = String::new();
                    }
                    _ => current.push(ch),
                }
            }
            
            // Add the last value
            let trimmed_current = current.trim();
            if trimmed_current == " " {
                values.push(String::new());
            } else {
                values.push(current);
            }
            
            Ok(lgpo::Action::MultiSz(values))
        }
        "-NODATA-" => Ok(lgpo::Action::Delete),
        unknown => Err(format!("Unknown registry action type: {}", unknown).into()),
    }
}

/// Converts a given lgpo::Action back to its string representation.
/// This function is the inverse of value_to_registry_action.
pub fn registry_action_to_value(action: &lgpo::Action) -> R<String> {
    match action {
        lgpo::Action::Sz(s) => Ok(format!("1,\"{}\"", s)),
        lgpo::Action::Binary(bytes) => {
            let num = u32::from_le_bytes(bytes.as_slice().try_into().unwrap());
            Ok(format!("3,{}", num))
        }
        lgpo::Action::Dword(num) => Ok(format!("4,{}", num)),
        lgpo::Action::MultiSz(values) => {
            let formatted_values: Vec<String> = values
                .iter()
                .map(|v| {
                    if v.is_empty() {
                        // Empty lines are represented as " " (quote-space-quote)
                        "\" \"".to_string()
                    } else if v.contains(',') || v.contains('"') {
                        // Lines with commas or quotes need to be quoted and quotes escaped
                        format!("\"{}\"", v.replace('"', "\"\""))
                    } else {
                        // Simple lines without commas or quotes
                        v.clone()
                    }
                })
                .collect();
            Ok(format!("7,{}", formatted_values.join(",")))
        }
        lgpo::Action::Delete => Ok("-NODATA-".to_string()),
        _ => Err("Unsupported action type".into()),
    }
}

/// # About
/// Exports LGPO settings to a local file, then parses them to build a SecEdit configuration.
/// # Errors
/// Returns an error if file export, file reading, or parsing fails.
fn get_secedit_config() -> R<SecEditConfig> {
    trace!("Exporting LGPO settings to retrieve SecEdit configuration");
    let secedit_file = lgpo_export(
        [PathBuf::from(
            "DomainSysvol\\GPO\\Machine\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf",
        )]
        .to_vec(),
    )?
    .remove(0);
    debug!(
        "LGPO export completed. Parsing SecEdit configuration from file: {:?}",
        secedit_file
    );
    let cfg_content = read_file_as_utf16_utf8(&secedit_file)?;
    let config_mapped: SecEditConfig = serde_ini::from_str(&cfg_content)?;
    debug!(
        "SecEdit configuration loaded successfully with {} sections",
        config_mapped.len()
    );
    Ok(config_mapped)
}

/// # About
/// Imports an updated SecEdit configuration to the system's Group Policy settings.
/// # Errors
/// Returns an error if the SecEdit config is uninitialized or import fails.
pub fn update_secedit_config() -> R<()> {
    trace!("Updating SecEdit configuration");
    let config = SECEDIT_CONFIG
        .get()
        .ok_or_else(|| "SecEdit configuration not initialized")?
        .lock()
        .unwrap()
        .clone();

    let raw_config = serde_ini::to_string(&config)?;
    let mut temp_file = tempfile::NamedTempFile::new()?;
    write_to_utf16(raw_config.clone(), temp_file.as_file_mut())?;
    debug!(
        "Temporary file created for updated SecEdit configuration at: {:?}",
        temp_file.path()
    );

    lgpo_import((
        LGPOCommands::SecurityTemplate,
        LGPOCommandArgs::NamedTempFile(&temp_file),
    ))?;
    debug!("SecEdit configuration imported successfully");

    Ok(())
}

impl<'de> Deserialize<'de> for ScopeValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s_trim = s.trim();

        let (key, value) = s_trim.split_once(':').unwrap_or((s_trim, ""));

        match key {
            "system_access" => Ok(ScopeValue::SystemAccess(value.to_string())),
            "privilege_rights" => {
                let ids = value.split(',').map(|id| id.to_string()).collect();
                Ok(ScopeValue::PrivilegeRights(ids))
            }
            "registry_values" => {
                let action = serde_plain::from_str(value).unwrap();
                Ok(ScopeValue::RegistryValues(action))
            }
            _ => Err(serde::de::Error::custom(format!(
                "Invalid scope line: {}",
                s_trim
            ))),
        }
    }
}

impl Serialize for ScopeValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let str = match self {
            ScopeValue::SystemAccess(value) => format!("system_access:{}", value),
            ScopeValue::PrivilegeRights(ids) => {
                let mut sorted_ids = ids.clone();
                sorted_ids.sort();
                let ids = sorted_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                format!("privilege_rights:{}", ids)
            }
            ScopeValue::RegistryValues(action) => {
                let action = serde_plain::to_string(action).unwrap();
                format!("registry_values:{}", action)
            }
        };

        serializer.serialize_str(&str)
    }
}
