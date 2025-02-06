use super::*;
use crate::methods::*;
use crate::traits::*;
use crate::utils::{datetime_to_filetime, filetime_to_epoch, gen_guid};
use chrono::{DateTime, Utc};
use lgpo::utils::get_lgpos;
use lgpo::LocalGroupPolicyObject;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{LockResult, Mutex, MutexGuard};
use windows::core::GUID;

/// This function organizes a list of LocalGroupPolicyObject into SoftwareRestrictionPolicy.
/// We group the LGPOs by security level, rule type, and GUID for structured processing.
fn parse_lgpos(lgpos: Vec<LocalGroupPolicyObject>) -> R<Vec<SoftwareRestrictionPolicy>> {
    trace!("Parsing LGPOs to SoftwareRestrictionPolicies");
    debug!("LGPOs: {:?}", lgpos);

    let re = Regex::new(
        r"^Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\(\d+)\\(Paths|UrlZones)\\(\{[0-9A-Fa-f\-]+\})$"
    ).unwrap();

    let mut policies = Vec::new();

    // Group LGPOs by their GUID
    let mut lgpo_map: HashMap<String, Vec<&LocalGroupPolicyObject>> = HashMap::new();
    for lgpo in &lgpos {
        if let Some(caps) = re.captures(&lgpo.registry_key) {
            let security_level = caps.get(1).unwrap().as_str().to_string();
            let rule_type = caps.get(2).unwrap().as_str().to_string();
            let guid = caps.get(3).unwrap().as_str().to_string();

            let key = format!("{}\\{}\\{}", security_level, rule_type, guid);
            lgpo_map.entry(key).or_default().push(lgpo);
        }
    }

    for (key, lgpo_group) in lgpo_map {
        // Split the key to get SecurityLevel, RuleType, and GUID
        let parts: Vec<&str> = key.split('\\').collect();
        let security_level_num: u32 = parts[0].parse()?;
        let security_level: SecurityLevel = match security_level_num {
            0 => SecurityLevel::Disallowed,
            131072 => SecurityLevel::BasicUser,
            262144 => SecurityLevel::Unrestricted,
            _ => continue, // Skip unknown security levels
        };

        let rule_type = match parts[1] {
            "Paths" => RuleType::Paths,
            "UrlZones" => RuleType::UrlZones,
            _ => continue, // Skip unsupported rule types
        };

        let guid: GUID = parts[2].trim_matches(|c| c == '{' || c == '}').into();

        let mut target = None;
        let mut description = None;
        let mut last_modified = None;

        for lgpo in lgpo_group {
            match lgpo.value_name.as_str() {
                "ItemData" => match (&rule_type, &lgpo.action) {
                    (RuleType::Paths, lgpo::Action::ExSz(path)) => {
                        target = Some(Target::Path(PathBuf::from(path)));
                    }
                    (RuleType::UrlZones, lgpo::Action::Dword(zone_num)) => {
                        let zone = match *zone_num as u32 {
                            0 => UrlZones::LocalMachine,
                            1 => UrlZones::LocalIntranet,
                            2 => UrlZones::TrustedSites,
                            3 => UrlZones::Internet,
                            4 => UrlZones::RestrictedSites,
                            _ => continue,
                        };
                        target = Some(Target::UrlZone(zone));
                    }
                    _ => {}
                },
                "Description" => {
                    if let lgpo::Action::Sz(desc) = &lgpo.action {
                        description = Some(desc.clone());
                    }
                }
                "LastModified" => {
                    if let lgpo::Action::Qword(filetime) = &lgpo.action {
                        let timestamp = filetime_to_epoch(*filetime as u64);
                        last_modified = DateTime::from_timestamp(timestamp, 0);
                    }
                }
                "SaferFlags" => {
                    // Value is always Dword(0), can be used for validation if needed
                }
                _ => {}
            }
        }

        if let Some(target) = target {
            let policy = SoftwareRestrictionPolicy {
                target,
                security_level: security_level.clone(),
                rule_type: rule_type.clone(),
                description: description.clone(),
                last_modified,
                lgpo_guid: Some(guid),
                state: State::Exists,
            };
            policies.push(policy);
        }
    }
    debug!("Parsed policies: {:?}", policies);
    Ok(policies)
}

pub fn get_global_state() -> LockResult<MutexGuard<'static, Vec<SoftwareRestrictionPolicy>>> {
    SAFER_RULES
        .get_or_init(|| Mutex::new(init_global_state().unwrap_or_default()))
        .lock()
}

/// This function initializes the global state if needed, ensuring required LGPO entries exist before parsing them.
fn init_global_state() -> R<Vec<SoftwareRestrictionPolicy>> {
    // // We check for missing minimal LGPOs to guarantee a functional baseline
    let lgpos: Vec<LocalGroupPolicyObject> = get_lgpos()?.to_owned();

    // debug!("Global state initialization process completed");

    parse_lgpos(lgpos)
}

/// This function identifies which minimal registry keys are missing in the given LGPO list.
fn get_missing_lgpo(lgpos: &Vec<LocalGroupPolicyObject>) -> R<Vec<LocalGroupPolicyObject>> {
    // We detect any minimal entries that do not exist
    let mut missing_registries = Vec::new();

    for safer_lgpo in &*SAFER_MINIMAL_REGISTRY_KEYS {
        let exists = lgpos.iter().any(|lgpo| lgpo == safer_lgpo);
        if !exists {
            missing_registries.push(safer_lgpo.clone());
        }
    }

    trace!("Gathered missing minimal registry entries");
    debug!("Missing minimal registry entries: {:?}", missing_registries);

    Ok(missing_registries)
}

/// This function creates the minimal missing LGPO entries required for a consistent safer policy setup.
fn create_missing_lgpo(missing_lgpo: Vec<LocalGroupPolicyObject>) -> R<()> {
    let _ = missing_lgpo.into_iter().map(|lgpo| {
        debug!("Creating missing LGPO: {:?}", lgpo);
        lgpo.execute().map_err(|e| {
            error!("Failed to create missing LGPO: {:?}", e);
            e
        })
    });

    debug!("Created or confirmed existence of missing LGPO entries");

    Ok(())
}

/// This function converts a list of SoftwareRestrictionPolicy into a vector of LocalGroupPolicyObject.
fn convert_policies_to_lgpos(
    policies: Vec<SoftwareRestrictionPolicy>,
) -> R<Vec<LocalGroupPolicyObject>> {
    // We build an LGPO representation for each policy for persistent storage
    let mut lgpos = Vec::new();

    for policy in policies {
        let guid = if policy.lgpo_guid.is_none() {
            gen_guid()?
        } else {
            policy.lgpo_guid.clone().unwrap()
        };
        let guid_str = format!("{{{:?}}}", guid);
        let security_level_num = match policy.security_level {
            SecurityLevel::Disallowed => 0,
            SecurityLevel::BasicUser => 131072,
            SecurityLevel::Unrestricted => 262144,
        };
        let rule_type_str = match policy.rule_type {
            RuleType::Paths => "Paths",
            RuleType::UrlZones => "UrlZones",
            _ => continue, // Skip unsupported rule types
        };
        let registry_base = format!(
            "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\{}\\{}\\{}",
            security_level_num, rule_type_str, guid_str
        );

        if policy.state == State::NotExists {
            // We skip policies that are marked as non-existent
            // `update_safer` will remove the corresponding LGPOs
            continue;
        }

        // ItemData
        let item_data_lgpo = match (&policy.rule_type, &policy.target) {
            (RuleType::Paths, Target::Path(path)) => LocalGroupPolicyObject {
                configuration: lgpo::Configuration::Computer,
                registry_key: registry_base.clone(),
                value_name: "ItemData".to_string(),
                action: lgpo::Action::ExSz(path.to_string_lossy().to_string()),
            },
            (RuleType::UrlZones, Target::UrlZone(zone)) => LocalGroupPolicyObject {
                configuration: lgpo::Configuration::Computer,
                registry_key: registry_base.clone(),
                value_name: "ItemData".to_string(),
                action: lgpo::Action::Dword(match zone {
                    UrlZones::LocalMachine => 0,
                    UrlZones::LocalIntranet => 1,
                    UrlZones::TrustedSites => 2,
                    UrlZones::Internet => 3,
                    UrlZones::RestrictedSites => 4,
                }),
            },
            _ => continue, // Skip if target and rule type do not match
        };
        lgpos.push(item_data_lgpo);

        // Description
        if let Some(desc) = &policy.description {
            let description_lgpo = LocalGroupPolicyObject {
                configuration: lgpo::Configuration::Computer,
                registry_key: registry_base.clone(),
                value_name: "Description".to_string(),
                action: lgpo::Action::Sz(format!("[{}] {}", env!("CARGO_CRATE_NAME"), desc)),
            };
            lgpos.push(description_lgpo);
        }

        let last_modified = match policy.last_modified {
            Some(dt) => dt,
            None => Utc::now(),
        };

        let filetime = datetime_to_filetime(last_modified.clone());
        let last_modified_lgpo = LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: registry_base.clone(),
            value_name: "LastModified".to_string(),
            action: lgpo::Action::Qword(filetime),
        };
        lgpos.push(last_modified_lgpo);

        // SaferFlags
        let safer_flags_lgpo = LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: registry_base.clone(),
            value_name: "SaferFlags".to_string(),
            action: lgpo::Action::Dword(0),
        };
        lgpos.push(safer_flags_lgpo);
    }

    trace!("Constructed SAFER LGPO objects from provided policies");

    Ok(lgpos)
}

/// This function updates SAFER rules by clearing existing dynamic ones and appending newly converted LGPO entries.
pub fn update_safer() -> R<()> {
    trace!("Updating SAFER rules");
    // We remove old targets, then convert and append new ones to keep them in sync
    // Get a mutable copy of the LGPOs
    let mut lgpos = get_lgpos()?;

    // Get the current safer rules from the global state
    let rules = get_global_state()?.to_owned();

    debug!("Current SAFER rules: {:?}", rules);

    // Convert the safer rules to LGPOs
    let safer_lgpos = convert_policies_to_lgpos(rules)?;

    // Remove existing LGPOs related to safer rules, excluding initialization entries
    let safer_lgpos_to_remove = lgpos
        .clone()
        .into_iter()
        .filter(|lgpo| is_safer_rule_lgpo(&lgpo))
        .collect::<Vec<_>>();

    lgpos.retain(|lgpo| !is_safer_rule_lgpo(lgpo));
    debug!("Removed existing SAFER rules LGPOs");
    debug!("retained lgpos: {:?}", lgpos);

    // For each non-retained lgpo, get the GUID and push a lgpo object with value_name "*" and action CLEAR
    let mut registry_keys_to_clear: HashSet<(lgpo::Configuration, String)> = HashSet::new();
    let re = Regex::new(
        r"^(Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\\d+\\(Paths|UrlZones)\\\{[0-9A-Fa-f\-]+\})",
    )
    .unwrap();

    for lgpo in safer_lgpos_to_remove {
        if let Some(caps) = re.captures(&lgpo.registry_key) {
            let registry_key = caps.get(1).unwrap().as_str().to_string();
            registry_keys_to_clear.insert((lgpo.configuration.clone(), registry_key));
        }
    }

    for (configuration, registry_key) in registry_keys_to_clear {
        let lgpo_clear = LocalGroupPolicyObject {
            configuration,
            registry_key,
            value_name: "*".to_string(),
            action: lgpo::Action::Clear,
        };
        lgpos.push(lgpo_clear);
    }

    if !safer_lgpos.is_empty() {
        debug!("Creating missing minimal LGPOs");
        let missing = get_missing_lgpo(&lgpos)?;
        if !missing.is_empty() {
            create_missing_lgpo(missing)?;
        }
    } else {
        debug!("No SAFER rules to add");
        debug!("Deleting minimal LGPOs");
        for safer_lgpo in &*SAFER_MINIMAL_REGISTRY_KEYS {
            let lgpo = LocalGroupPolicyObject {
                configuration: lgpo::Configuration::Computer,
                registry_key: safer_lgpo.registry_key.to_string(),
                value_name: "*".to_string(),
                action: lgpo::Action::Clear,
            };
            lgpos.push(lgpo);
        }
    }

    // Append the new safer rules LGPOs
    lgpos.extend(safer_lgpos);

    debug!("Updated LGPOs: {:?}", lgpos);

    Ok(())
}

/// Checks if a LocalGroupPolicyObject belongs to a SAFER rule (excluding initial configuration keys).
fn is_safer_rule_lgpo(lgpo: &LocalGroupPolicyObject) -> bool {
    let key = &lgpo.registry_key;

    // Skip initialization keys
    let initialization_keys =
        vec!["Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers"];

    if initialization_keys.contains(&key.as_str()) {
        return false;
    }

    // Check if the key starts with the safer rules path
    key.starts_with("Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\")
}
