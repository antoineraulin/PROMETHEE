use super::utils::*;
use super::*;
use crate::methods::*;
use crate::traits::*;

impl RuleTrait for FirewallRule {
    fn execute(&self) -> R<()> {
        trace!("Executing firewall rule: {}", self.rule_name);

        // Retrieve the current value of the rule.
        let current_raw = self.current_value()?;
        let current_rule = FirewallRule::from_raw(current_raw)?;

        // If the rule exists, delete it first.
        if current_rule.action != Action::NoExists {
            delete_firewall_rule(self.rule_name.clone())?;
        }

        // Create the firewall rule.
        create_firewall_rule(self.clone())
    }

    fn current_value(&self) -> R<RawMethod> {
        trace!(
            "Retrieving current value for firewall rule: {}",
            self.rule_name
        );
        let rule: FirewallRule = match get_rule(self.rule_name.clone()) {
            Ok(rule) => rule,
            Err(_) => {
                let mut rule = self.clone();
                rule.action = Action::NoExists;
                rule
            }
        };
        Ok(rule.to_raw(false))
    }

    fn to_raw(&self, _compare_mode: bool) -> RawMethod {
        RawMethod {
            method: "firewall".to_string(),
            target: self.rule_name.clone(),
            action: serde_plain::to_string(&self.action).unwrap(),
            option1: serde_plain::to_string(&self.direction).unwrap(),
            option2: format!(
                "{}/{}",
                serde_plain::to_string(&self.protocol).unwrap(),
                serde_plain::to_string(&self.local_port).unwrap()
            ),
            scope: self
                .profiles
                .iter()
                .map(|p| serde_plain::to_string(p).unwrap())
                .collect::<Vec<String>>()
                .join(","),
        }
    }

    fn from_raw(raw: RawMethod) -> R<Self>
    where
        Self: Sized,
    {
        let action: Action = serde_plain::from_str(&raw.action).unwrap();
        let direction: Direction = serde_plain::from_str(&raw.option1).unwrap();
        let (protocol, local_port) = {
            let parts: Vec<&str> = raw.option2.split('/').collect();
            let protocol: Protocol = serde_plain::from_str(parts[0]).unwrap();
            let local_port: Port = serde_plain::from_str(parts[1]).unwrap();
            (protocol, local_port)
        };
        let profiles: Vec<Profile> = raw
            .scope
            .split(',')
            .map(|p| serde_plain::from_str(p).unwrap())
            .collect();

        Ok(FirewallRule {
            rule_name: raw.target,
            action,
            direction,
            protocol,
            local_port,
            profiles,
        })
    }
}
