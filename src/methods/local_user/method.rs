use super::utils::*;
use super::*;
use crate::local_group::{
    self,
    utils::{add_sid_to_groups, get_groups_for_account},
};
use crate::methods::*;
use crate::traits::*;

/// Implementation of the `Rule` trait for `LocalAccount`.
impl RuleTrait for LocalAccount {
    /// Executes the specified action on the local account.
    ///
    /// This function checks the current state of the account and determines if any action is required to achieve the desired state.
    fn execute(&self) -> R<()> {
        trace!("Executing LocalAccount rule {:?}", self);

        // Retrieve the current state of the local account
        let current_value = Self::from_raw(self.current_value()?)?;
        debug!("Current value: {:?}", current_value);

        // converting the group names to SIDs
        let groups_to_be_part_of: Vec<String> = self
            .groups
            .iter()
            .map(|group| match local_group::utils::get_type(group) {
                local_group::IdType::Name => {
                    debug!("Resolving group name '{}' to SID", group);
                    match account_name_to_sid(group) {
                        Ok(sid) => sid,
                        Err(e) => {
                            warn!(
                                "Failed to resolve group name '{}': {}. Defaulting to using the provided group as SID.",
                                group, e
                            );
                            group.clone()
                        }
                    }
                }
                local_group::IdType::SID => {
                    debug!("Using existing SID '{}' for group", group);
                    group.clone()
                }
            })
            .collect();

        let current_value_groups_as_sid = current_value
            .groups
            .iter()
            .map(|group| match local_group::utils::get_type(group) {
                local_group::IdType::Name => {
                    debug!("Resolving group name '{}' to SID", group);
                    account_name_to_sid(group).unwrap()
                }
                local_group::IdType::SID => {
                    debug!("Using existing SID '{}' for group", group);
                    group.clone()
                }
            })
            .collect::<Vec<String>>();

        let current_value_id_as_sid = match get_type(&current_value.id) {
            IdType::Username => match account_name_to_sid(&current_value.id) {
                Ok(sid) => sid,
                Err(e) => {
                    warn!(
                            "Failed to resolve account name '{}': {}. Defaulting to using the provided ID as SID.",
                            current_value.id, e
                        );
                    current_value.id.clone()
                }
            },
            IdType::SID => current_value.id.clone(),
            IdType::RID => rid_to_sid(current_value.id.parse::<u16>().unwrap())?,
        };

        // Determine if an action is needed by comparing the desired action with the current state
        let action = if current_value.action != self.action
            || current_value_groups_as_sid != groups_to_be_part_of
        {
            Some(self.action.clone())
        } else {
            None
        };

        if let Some(action) = action {
            match action {
                Action::Enabled => {
                    // Enable the user account or create it if it doesn't exist
                    let user_sid = if current_value.action == Action::NotExist {
                        trace!("User does not exist, creating user '{}'", self.id);
                        // Create a new user account
                        create_user(&self.id)?
                    } else {
                        trace!(
                            "User exists but is disabled, enabling user '{}'",
                            current_value_id_as_sid
                        );
                        // Enable the existing user account
                        enable_local_user(&current_value_id_as_sid)?
                    };
                    debug!("User SID: {}", user_sid);

                    // Add the user to the specified groups
                    trace!(
                        "Adding user '{}' to groups {:?}",
                        user_sid,
                        groups_to_be_part_of
                    );
                    add_sid_to_groups(&user_sid, groups_to_be_part_of.clone())?;
                }
                Action::Disabled => {
                    // Disable the user account
                    let sid = current_value_id_as_sid;
                    trace!("Disabling user '{}'", sid);
                    disable_local_user(&sid)?;
                }
                Action::NotExist => {
                    let sid = current_value_id_as_sid;
                    // Delete the user account
                    trace!("Deleting user '{}'", sid);
                    delete_local_user(&sid)?;
                }
            }
        } else {
            trace!("No action required for user '{}'", self.id);
        }

        Ok(())
    }

    /// Retrieves the current state of the local account.
    ///
    /// This function determines the account's SID, status, and group memberships to establish its current state.
    fn current_value(&self) -> R<RawMethod> {
        trace!("Retrieving current value for LocalAccount {:?}", self);

        let id_type = get_type(&self.id);

        // Resolve the SID based on the identifier type (Username, SID, RID)
        let sid = match id_type {
            IdType::Username => {
                // Convert username to SID
                trace!("ID '{}' is a Username", self.id);
                account_name_to_sid(&self.id)
            }
            IdType::SID => {
                // Use the provided SID directly
                trace!("ID '{}' is a SID", self.id);
                Ok(self.id.clone())
            }
            IdType::RID => {
                // Convert RID to SID
                trace!("ID '{}' is a RID", self.id);
                rid_to_sid(self.id.parse::<u16>().unwrap())
            }
        };
        let sid = match sid {
            Ok(sid) => {
                debug!("Resolved SID: {}", sid);
                sid
            }
            Err(e) => {
                warn!(
                    "Failed to resolve SID: {}. This could indicate the account does not exist.",
                    e
                );
                self.id.clone()
            }
        };

        // Get the account's current action status (Enabled, Disabled, NotExist)
        let status = get_user_account_status_from_sid(&sid);

        let ok = match status {
            Ok(Action::NotExist) => false,
            Err(_) => false,
            _ => true,
        };

        if !ok {
            warn!("Failed to retrieve account status for SID '{}'", sid);
            warn!("Considering account does not exist");
            let mut account = self.clone();
            account.action = Action::NotExist;
            return Ok(account.to_raw(false));
        }

        let status = status.unwrap();

        debug!("Account status: {:?}", status);

        // Retrieve the groups the account is currently a member of
        let groups = match get_groups_for_account(sid.clone()) {
            Ok(groups) => groups,
            Err(e) => {
                warn!("Failed to retrieve groups for account '{}': {}. Defaulting to no groups to be part of.", sid, e);
                vec![]
            }
        };
        debug!("Current groups: {:?}", groups);

        let id = match id_type {
            IdType::Username => sid_to_account_name(&sid)?,
            IdType::SID => sid.clone(),
            IdType::RID => sid_to_rid(&sid)?,
        };

        let groups_original_type: local_group::IdType = match self
            .groups
            .first()
            .map(|group| local_group::utils::get_type(group))
        {
            Some(t) => t,
            None => local_group::IdType::SID,
        };

        let mut new_groups = vec![];

        debug!(
            "Converting group SIDs to original type: {:?}",
            groups_original_type
        );

        for group in groups.iter() {
            let g = match groups_original_type {
                local_group::IdType::Name => sid_to_account_name(&group)?,
                local_group::IdType::SID => group.clone(),
            };
            new_groups.push(g);
        }

        // Return the current state as a new LocalAccount instance
        Ok(LocalAccount {
            id,
            groups: new_groups,
            action: status,
        }
        .to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "local_user".to_string(),
            target: self.id.clone(),
            option1: self.groups.join(","),
            option2: "".to_string(),
            scope: "".to_string(),
            action: serde_plain::to_string(&self.action).unwrap(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        Ok(LocalAccount {
            id: raw.target,
            groups: raw.option1.split(',').map(|s| s.to_string()).collect(),
            action: serde_plain::from_str(&raw.action).unwrap(),
        })
    }
}
