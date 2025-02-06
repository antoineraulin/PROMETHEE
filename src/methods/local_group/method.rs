use log::{debug, trace};

use super::data_structure::*;
use super::utils::*;
use crate::local_user::utils::account_name_to_sid;
use crate::methods::local_user::utils::sid_to_account_name;
use crate::methods::*;
use crate::traits::*;

use super::data_structure::LocalGroup;

/// Implementation of the `Rule` trait for `LocalGroup`.
impl RuleTrait for LocalGroup {
    /// Executes the specified action on the local group.
    ///
    /// This function checks the current state of the group and determines if any action is required to achieve the desired state.
    fn execute(&self) -> R<()> {
        trace!("Executing LocalGroup rule {:?}", self);

        // Retrieve the current state of the local group
        let current_value = Self::from_raw(self.current_value()?)?;
        debug!("Current value: {:?}", current_value);

        // Determine if an action is needed by comparing the desired action with the current state
        let action = if current_value.action != self.action {
            Some(self.action.clone())
        } else {
            None
        };

        if let Some(action) = action {
            match action {
                Action::Exist => {
                    // Create the group if it does not exist
                    trace!("Creating group '{}'", self.id);
                    let sid = create_local_group(&self.id)?;
                    debug!("Group SID: {}", sid);
                }
                Action::NotExist => {
                    // Delete the group if it exists
                    let sid = match get_type(&self.id) {
                        IdType::Name => account_name_to_sid(&self.id)?,
                        IdType::SID => self.id.clone(),
                    };
                    trace!("Deleting group with SID '{}'", sid);
                    delete_local_group(&sid)?;
                }
            }
        } else {
            trace!("No action required for group '{}'", self.id);
        }

        Ok(())
    }

    /// Retrieves the current state of the local group.
    ///
    /// This function determines the group's SID, memberships, and existence to establish its current state.
    fn current_value(&self) -> R<RawMethod>
    where
        Self: Sized,
    {
        trace!("Retrieving current value for LocalGroup {:?}", self);

        let id_type = get_type(&self.id);

        let sid = match id_type {
            IdType::Name => account_name_to_sid(&self.id),
            IdType::SID => Ok(self.id.clone()),
        };

        if sid.is_err() {
            warn!("Failed to resolve SID for group '{}'", self.id);
            warn!("Considering group does not exist");
            let mut group = self.clone();
            group.action = Action::NotExist;
            return Ok(group.to_raw(false));
        }

        let sid = sid.unwrap();
        debug!("Resolved SID for group '{}': {}", self.id, sid);

        // Get the current members of the group
        let members = get_group_members(&sid)?;
        debug!("Current members of group '{}': {:?}", self.id, members);

        //  return id as the same type as original for audit comparison
        let id = match id_type {
            IdType::Name => sid_to_account_name(&sid),
            IdType::SID => Ok(self.id.clone()),
        };

        if id.is_err() {
            warn!("Failed to resolve account name for SID '{}'", sid);
            return Err(format!("Failed to resolve account name : {}", id.err().unwrap()).into());
        }

        // Return the current state as a new LocalGroup instance
        Ok(LocalGroup {
            id: id.unwrap(),
            members,
            action: Action::Exist,
        }
        .to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "local_group".to_string(),
            target: self.id.clone(),
            action: serde_plain::to_string(&self.action).unwrap(),
            option1: "".to_string(),
            option2: "".to_string(),
            scope: "".to_string(),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let action: local_group::Action = serde_plain::from_str(&raw.action)
            .map_err(|e| format!("Invalid action '{}' : {}", raw.action, e))?;

        Ok(LocalGroup {
            id: raw.target,
            members: vec![],
            action,
        })
    }
}
