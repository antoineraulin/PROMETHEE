use super::data_structure::*;
use crate::local_user::utils::{account_name_to_sid, validate_sid};
use crate::traits::*;
use std::process::Command;

/// Retrieves all local groups on the system.
///
/// This function executes a PowerShell command to list all local groups and constructs
/// `LocalGroup` objects for each one.
pub fn get_local_groups() -> R<Vec<LocalGroup>> {
    trace!("Retrieving local groups");

    // Execute PowerShell command to get local groups
    let output = Command::new("powershell")
        .args(&["-Command", "Get-LocalGroup | Select-Object SID"])
        .output()?;

    let output = String::from_utf8_lossy(&output.stdout);

    // Parse the output to get group SIDs
    let groups: Vec<LocalGroup> = output
        .lines()
        .skip(3) // Skip header and empty lines
        .map(|line| {
            let sid = line.trim().to_string();

            // Get members of the group
            let members = get_group_members(&sid).unwrap_or_else(|_| vec![]);

            LocalGroup {
                id: sid,
                members,
                action: Action::Exist,
            }
        })
        .collect();

    debug!("Found {} local groups", groups.len());
    Ok(groups)
}

/// Retrieves members of a local group given its SID.
///
/// Executes a PowerShell command to list all members of the specified group.
pub fn get_group_members(sid: &str) -> R<Vec<String>> {
    trace!("Retrieving members for group SID: {}", sid);

    // Execute PowerShell command to get group members
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!("Get-LocalGroupMember -SID {} | Select-Object SID", sid),
        ])
        .output()?;

    let output = String::from_utf8_lossy(&output.stdout);

    // Parse the output to get member SIDs
    let members: Vec<String> = output
        .lines()
        .skip(3) // Skip header and empty lines
        .map(|line| line.trim().to_string())
        .collect();

    debug!("Group SID {} has {} members", sid, members.len());
    Ok(members)
}

/// Retrieves all local groups that an account SID belongs to.
///
/// This function helps in determining group memberships for a specific account.
pub fn get_groups_for_account(sid: String) -> R<Vec<String>> {
    trace!("Getting groups for account SID: {}", sid);

    // Get all local groups
    let groups = get_local_groups()?;

    // Filter groups where the account is a member
    let user_groups: Vec<String> = groups
        .into_iter()
        .filter(|group| group.members.contains(&sid))
        .map(|group| group.id)
        .collect();

    debug!(
        "Account SID {} is a member of {} groups",
        sid,
        user_groups.len()
    );
    Ok(user_groups)
}

/// Adds an account SID to multiple local groups specified by their SIDs.
///
/// This function automates adding an account to several groups at once.
pub fn add_sid_to_groups(sid_to_add: &str, group_sids: Vec<String>) -> R<()> {
    trace!("Adding SID {} to groups", sid_to_add);

    for group_sid in group_sids {
        debug!(
            "Adding account SID {} to group SID {}",
            sid_to_add, group_sid
        );

        // Execute PowerShell command to add the account to the group
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Add-LocalGroupMember -SID {} -Member {}",
                    group_sid, sid_to_add
                ),
            ])
            .output()?;

        // Check if the command was successful
        if !output.status.success() {
            warn!(
                "Failed to add account SID {} to group SID {}",
                sid_to_add, group_sid
            );
        }
    }
    Ok(())
}

/// Determines whether an identifier is a SID or a Name.
///
/// Uses SID validation to check the identifier type.
pub fn get_type(id: &str) -> IdType {
    trace!("Determining ID type for: {}", id);

    if validate_sid(id).unwrap_or(false) {
        IdType::SID
    } else {
        IdType::Name
    }
}

/// Creates a new local group with the given name.
///
/// This function is useful for setting up new groups programmatically.
pub fn create_local_group(name: &str) -> R<String> {
    trace!("Creating local group: {}", name);

    // Execute PowerShell command to create the group
    let create_cmd = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "New-LocalGroup -Name {} -Description 'Created by {}'",
                name,
                env!("CARGO_CRATE_NAME")
            ),
        ])
        .output()?;

    // Check if the command was successful
    if !create_cmd.status.success() {
        warn!("Failed to create group: {}", name);
        return Err("Failed to create group".into());
    }

    // Get the SID of the newly created group
    let sid = account_name_to_sid(name)?;
    debug!("Created group '{}' with SID: {}", name, sid);

    Ok(sid)
}

/// Deletes a local group specified by its SID.
///
/// This function removes groups that are no longer needed.
pub fn delete_local_group(sid: &str) -> R<()> {
    trace!("Deleting local group with SID: {}", sid);

    // Execute PowerShell command to delete the group
    let delete_cmd = Command::new("powershell")
        .args(&["-Command", &format!("Remove-LocalGroup -SID {}", sid)])
        .output()?;

    // Check if the command was successful
    if !delete_cmd.status.success() {
        warn!("Failed to delete group with SID: {}", sid);
        return Err("Failed to delete group".into());
    }

    debug!("Deleted group with SID: {}", sid);
    Ok(())
}
