use super::data_structure::*;
use crate::traits::*;
use std::process::Command;
use winsafe::LookupAccountSid;
use winsafe::{
    ConvertSidToStringSid, ConvertStringSidToSid, GetComputerName, IsValidSid, LookupAccountName,
};

/// Determines the type of identifier provided (SID, RID, or Username).
///
/// This is important because different types require different handling methods.
pub fn get_type(id: &str) -> IdType {
    trace!("Determining ID type for: {}", id);
    // Check if the ID is a valid SID
    if validate_sid(id).unwrap_or(false) {
        return IdType::SID;
    }
    // Check if the ID is a numeric RID
    if let Ok(_) = id.parse::<u16>() {
        return IdType::RID;
    }
    // Default to Username if not SID or RID
    IdType::Username
}

/// Retrieves the computer's SID.
///
/// The computer SID is used as a base for constructing full SIDs for local accounts.
pub fn get_computer_sid() -> R<String> {
    trace!("Retrieving computer SID");
    let computer_name = GetComputerName()?;
    // Convert the computer name to its corresponding SID
    account_name_to_sid(&computer_name)
}

/// Converts an account name to a SID string.
///
/// Many system operations require the SID; this conversion facilitates those operations.
pub fn account_name_to_sid(username: &str) -> R<String> {
    trace!("Converting account name '{}' to SID", username);
    // Lookup the account's SID using the account name
    let (_, sid, _) = LookupAccountName(None, username)?;
    ConvertSidToStringSid(&sid).map_err(|e| e.into())
}

/// Converts a SID string to an account name.
///
/// This is the inverse operation of account_name_to_sid.
pub fn sid_to_account_name(sid_str: &str) -> R<String> {
    trace!("Converting SID '{}' to account name", sid_str);
    // Convert the SID string to its corresponding PSID
    let sid_ptr = ConvertStringSidToSid(sid_str);

    match sid_ptr {
        Ok(sid_ptr) => {
            // Lookup the account name using the SID
            let (name, _, _) = LookupAccountSid(None, &sid_ptr)?;
            Ok(name)
        }
        Err(_) => Ok(sid_str.to_string()),
    }
}

/// Converts a RID to a SID string by appending it to the computer SID.
///
/// This is necessary when only the RID is known, but the full SID is required.
pub fn rid_to_sid(rid: u16) -> R<String> {
    trace!("Converting RID '{}' to SID", rid);
    // Construct the SID by combining the computer SID and the RID
    let sid_str = format!("{}-{}", &*COMPUTER_SID, rid);
    // Validate the constructed SID
    validate_sid(&sid_str)?;
    Ok(sid_str)
}

/// Converts a SID string to a RID by extracting the trailing numeric component.
///
/// This is the inverse operation of rid_to_sid, and depends on the SID being in the format
/// "COMPUTER_SID-RID". It returns an error if the SID does not conform to the expected format
/// or if parsing the RID fails.
pub fn sid_to_rid(sid_str: &str) -> R<String> {
    trace!("Converting SID '{}' to RID", sid_str);
    let computer_sid_prefix = format!("{}-", &*COMPUTER_SID);
    if !sid_str.starts_with(&computer_sid_prefix) {
        return Err("SID does not start with the computer SID".into());
    }
    let rid_part = &sid_str[computer_sid_prefix.len()..];
    Ok(rid_part.to_string())
}

/// Validates if the provided SID string is a valid SID.
///
/// Ensures that the SID can be used safely in system operations.
pub fn validate_sid(sid_str: &str) -> R<bool> {
    trace!("Validating SID '{}'", sid_str);
    // Convert the SID string to a PSID
    let sid_ptr = ConvertStringSidToSid(sid_str)?;
    // Check if the SID is valid
    IsValidSid(&sid_ptr).map_err(|e| e.into())
}

/// Retrieves the account status (Enabled, Disabled, NotExist) from a SID.
///
/// This helps determine what action to take on the account.
pub fn get_user_account_status_from_sid(sid_str: &str) -> R<Action> {
    trace!("Getting account status for SID '{}'", sid_str);
    // Execute PowerShell command to get the 'Enabled' property
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "Get-LocalUser -SID {} | Select-Object -ExpandProperty Enabled",
                sid_str
            ),
        ])
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                warn!("Account does not exist for SID '{}'", sid_str);
                return Ok(Action::NotExist);
            }
            // Parse the output to determine if the account is enabled
            let enabled = String::from_utf8_lossy(&output.stdout)
                .trim()
                .eq_ignore_ascii_case("True");
            if enabled {
                Ok(Action::Enabled)
            } else {
                Ok(Action::Disabled)
            }
        }
        Err(e) => {
            warn!("Failed to get account status for SID '{}': {}", sid_str, e);
            Ok(Action::NotExist)
        }
    }
}

/// Creates a new local user with the given username.
///
/// The user is created without a password and is marked with a description for identification.
pub fn create_user(username: &str) -> R<String> {
    trace!("Creating user '{}'", username);
    // Use PowerShell to create the local user account
    let create_cmd = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "New-LocalUser -Name '{}' -NoPassword -Description 'Created by {}'",
                username,
                env!("CARGO_CRATE_NAME")
            ),
        ])
        .output()?;

    if !create_cmd.status.success() {
        warn!("Failed to create user '{}'", username);
        return Err("Failed to create user".into());
    }

    // Retrieve the SID of the newly created user
    let sid = account_name_to_sid(username)?;

    // Set the password policy for the user
    let set_cmd = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "Set-LocalUser -SID {} -PasswordNeverExpires $false",
                sid.clone()
            ),
        ])
        .output()?;

    if !set_cmd.status.success() {
        warn!("Failed to set password policy for user '{}'", username);
        return Err("Failed to set user password policy".into());
    }

    Ok(sid)
}

/// Enables a local user account based on the given SID.
///
/// Necessary when reactivating a previously disabled account.
pub fn enable_local_user(sid: &str) -> R<String> {
    trace!("Enabling user with SID '{}'", sid);
    // Use PowerShell to enable the user account
    let output = Command::new("powershell")
        .args(&["-Command", &format!("Enable-LocalUser -SID {}", sid)])
        .output()?;

    if !output.status.success() {
        warn!("Failed to enable user with SID '{}'", sid);
        return Err("Failed to enable user".into());
    }

    Ok(sid.to_string())
}

/// Disables a local user account based on the given SID.
///
/// This prevents the user from logging in without deleting the account.
pub fn disable_local_user(sid: &str) -> R<()> {
    trace!("Disabling user with SID '{}'", sid);
    // Use PowerShell to disable the user account
    let output = Command::new("powershell")
        .args(&["-Command", &format!("Disable-LocalUser -SID {}", sid)])
        .output()?;

    if !output.status.success() {
        warn!("Failed to disable user with SID '{}'", sid);
        return Err("Failed to disable user".into());
    }

    Ok(())
}

/// Deletes a local user account based on the given SID.
///
/// Permanently removes the user from the system.
pub fn delete_local_user(sid: &str) -> R<()> {
    trace!("Deleting user with SID '{}'", sid);
    // Use PowerShell to remove the user account
    let output = Command::new("powershell")
        .args(&["-Command", &format!("Remove-LocalUser -SID {}", sid)])
        .output()?;

    if !output.status.success() {
        warn!("Failed to delete user with SID '{}'", sid);
        return Err("Failed to delete user".into());
    }

    Ok(())
}
