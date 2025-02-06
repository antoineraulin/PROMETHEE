use std::process::Command;

use log::{debug, trace, warn};
use serde::{
    de::{Error as DeError, Unexpected},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::traits::R;

use super::*;

/// Retrieves an existing firewall rule by its display name.
///
/// # Why
/// We rely on Windows Powershell Cmdlets for simplicity and reliability,
/// rather than reimplementing Windows Firewall APIs in Rust.
///
/// # Errors
/// Returns an error if the Powershell command fails or no matching rule is found.
pub fn get_rule(display_name: String) -> R<FirewallRule> {
    debug!(
        "Attempting to retrieve firewall rule with name: {}",
        display_name
    );

    let command = format!("Get-NetFirewallRule | Where DisplayName -eq \"{}\" | Select DisplayName,Description,Enabled,Profile,Direction,Action | ConvertTo-Json", display_name);

    debug!("`get_rule` 1st command : `{}`", command);

    let output = Command::new("powershell")
        .args(&["-Command", command.as_str()])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    debug!("`get_rule` 1st command output : {}", stdout);

    if !output.stderr.is_empty() {
        return Err("No rule found with the specified display name.".into());
    }

    let rule_raw: FirewallRuleRaw = serde_json::from_slice(&output.stdout).map_err(|e| {
        warn!("Failed to parse rule data: {}", e);
        e
    })?;

    let command2 = format!(
        "Get-NetFirewallRule | Where DisplayName -eq \"{}\" | Get-NetFirewallPortFilter | Select Protocol,LocalPort | ConvertTo-Json",
        display_name
    );

    debug!("`get_rule` 2nd command : `{}`", command2);

    let port_output = Command::new("powershell")
        .args(&["-Command", command2.as_str()])
        .output()?;

    let stdout = String::from_utf8_lossy(&port_output.stdout);

    debug!("`get_rule` 2nd command output : {}", stdout);

    if !port_output.stderr.is_empty() {
        return Err("No port filter found for the specified display name.".into());
    }

    let port_filter_raw: FirewallPortFilterRaw = serde_json::from_slice(&port_output.stdout)
        .map_err(|e| {
            warn!("Failed to parse port filter data: {}", e);
            e
        })?;

    construct_firewall_rule(rule_raw, port_filter_raw)
}

/// Constructs a `FirewallRule` from raw firewall rule and port filter data.
///
/// # Parameters
/// - `rule_raw`: The raw firewall rule data.
/// - `port_filter_raw`: The raw firewall port filter data.
///
/// # Returns
/// A `FirewallRule` object constructed from the provided raw data.
///
/// # Errors
/// Returns an error if any of the fields in the raw data are invalid.
///
/// # Example
/// ```rust
/// let firewall_rule = construct_firewall_rule(rule_raw, port_filter_raw)?;
/// ```
fn construct_firewall_rule(
    rule_raw: FirewallRuleRaw,
    port_filter_raw: FirewallPortFilterRaw,
) -> R<FirewallRule> {
    debug!("Starting construction of FirewallRule from raw data.");

    let local_port = match port_filter_raw.local_port {
        LocalPort::Any(_) => Port::Any,
        LocalPort::List { value, count } => {
            if count == 1 {
                let port = value[0].parse::<u16>()?;
                Port::List(vec![PortSpec::Single(port)])
            } else {
                let ports: Vec<PortSpec> = value
                    .iter()
                    .map(|p| {
                        if let Some(range) = p.split('-').collect::<Vec<&str>>().get(0..2) {
                            if range.len() == 2 {
                                let start = range[0].parse::<u16>()?;
                                let end = range[1].parse::<u16>()?;
                                Ok(PortSpec::Range { start, end })
                            } else {
                                let port = range[0].parse::<u16>()?;
                                Ok(PortSpec::Single(port))
                            }
                        } else {
                            let port = p.parse::<u16>()?;
                            Ok(PortSpec::Single(port))
                        }
                    })
                    .collect::<Result<Vec<PortSpec>, std::num::ParseIntError>>()?;
                Port::List(ports)
            }
        }
    };

    trace!("Parsed local port: {:?}", local_port);

    // Map raw action
    let action = match rule_raw.action {
        2 => Action::Allow,
        4 => Action::Block,
        _ => {
            warn!(
                "Unknown action value: {}. Defaulting to Block.",
                rule_raw.action
            );
            Action::Block
        }
    };

    trace!("Mapped action: {:?}", action);

    // Map raw direction
    let direction = match rule_raw.direction {
        1 => Direction::Inbound,
        0 => Direction::Outbound,
        _ => {
            warn!(
                "Unknown direction value: {}. Defaulting to Ingress.",
                rule_raw.direction
            );
            Direction::Inbound
        }
    };

    trace!("Mapped direction: {:?}", direction);

    // Map raw profiles
    let profiles = match rule_raw.profile {
        0 => vec![Profile::Any],
        1 => vec![Profile::Domain],
        2 => vec![Profile::Private],
        3 => vec![Profile::Domain, Profile::Private],
        4 => vec![Profile::Public],
        5 => vec![Profile::Domain, Profile::Public],
        6 => vec![Profile::Private, Profile::Public],
        _ => {
            warn!(
                "Unknown profile value: {}. Defaulting to Domain.",
                rule_raw.profile
            );
            vec![Profile::Domain]
        }
    };

    debug!("Mapped profiles: {:?}", profiles);

    Ok(FirewallRule {
        rule_name: rule_raw.display_name,
        action,
        direction,
        protocol: port_filter_raw.protocol,
        local_port,
        profiles,
    })
}

/// Creates a new firewall rule.
///
/// # Why
/// We build a Powershell command dynamically to accommodate all rule fields.
/// This approach gives us a clear, easily debuggable way to create rules.
///
/// # Errors
/// Returns an error if the command execution or argument serialization fails.
pub fn create_firewall_rule(rule: FirewallRule) -> R<()> {
    debug!("Assembling Powershell command for new firewall rule");

    if rule.action == Action::NoExists {
        warn!("Cannot create a rule with Action::NoExists. Called delete instead.");
        return delete_firewall_rule(rule.rule_name);
    }

    let mut command = format!(
        "New-NetFirewallRule -DisplayName \"{}\" -Action {} -Direction {} -Protocol {} {}",
        rule.rule_name,
        serde_plain::to_string(&rule.action)?,
        serde_plain::to_string(&rule.direction)?,
        serde_plain::to_string(&rule.protocol)?,
        if rule.protocol != Protocol::ICMP {
            format!("-LocalPort {}", serde_plain::to_string(&rule.local_port)?)
        } else {
            "".to_string()
        }
    );

    for profile in &rule.profiles {
        command.push_str(&format!(" -Profile {}", serde_plain::to_string(profile)?));
    }

    debug!("Powershell command: {}", command);

    trace!("Executing Powershell command to create firewall rule");
    let out = Command::new("powershell")
        .args(&["-Command", command.as_str()])
        .output();

    match out {
        Ok(output) => {
            if !output.status.success() {
                warn!("Failed to create firewall rule: {}", rule.rule_name);
                return Err(
                    format!("Failed to create firewall rule : {:#?}", output.stderr).into(),
                );
            }
        }
        Err(e) => {
            warn!("Failed to execute Powershell command: {}", e);
            return Err(format!("Failed to execute Powershell command : {}", e).into());
        }
    }

    Ok(())
}

/// Deletes a firewall rule.
///
/// Deletes the firewall using its display name.
pub fn delete_firewall_rule(display_name: String) -> R<()> {
    debug!("Deleting firewall rule with display name: {}", display_name);

    let command = format!(
        "Get-NetFirewallRule | Where DisplayName -eq \"{}\" | Remove-NetFirewallRule",
        display_name
    );

    trace!("Executing Powershell command to delete firewall rule");
    Command::new("powershell")
        .args(&["-Command", command.as_str()])
        .output()?;

    Ok(())
}

impl Serialize for Port {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Port::Any => serializer.serialize_str("Any"),
            Port::List(ports) => {
                let mut parts = vec![];
                for spec in ports {
                    match spec {
                        PortSpec::Single(p) => parts.push(p.to_string()),
                        PortSpec::Range { start, end } => {
                            parts.push(format!("{}-{}", start, end));
                        }
                    }
                }
                serializer.serialize_str(&parts.join(","))
            }
        }
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == "Any" {
            return Ok(Port::Any);
        }

        let mut specs = vec![];
        for chunk in s.split(',') {
            if let Some((start, end)) = chunk.split_once('-') {
                let start_num = start
                    .parse::<u16>()
                    .map_err(|_| DeError::invalid_value(Unexpected::Str(start), &"a valid port"))?;
                let end_num = end
                    .parse::<u16>()
                    .map_err(|_| DeError::invalid_value(Unexpected::Str(end), &"a valid port"))?;
                specs.push(PortSpec::Range {
                    start: start_num,
                    end: end_num,
                });
            } else {
                let single_num = chunk
                    .parse::<u16>()
                    .map_err(|_| DeError::invalid_value(Unexpected::Str(chunk), &"a valid port"))?;
                specs.push(PortSpec::Single(single_num));
            }
        }
        Ok(Port::List(specs))
    }
}
