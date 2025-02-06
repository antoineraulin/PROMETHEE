use serde::{Deserialize, Serialize};

/// Represents a firewall rule with its properties.
/// This struct defines all necessary information for a firewall rule.
#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub rule_name: String,
    pub action: Action,
    pub direction: Direction,
    pub protocol: Protocol,
    pub local_port: Port,
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FirewallRuleRaw {
    pub display_name: String,
    pub description: Option<String>,
    pub enabled: u8,
    pub action: u8,
    pub direction: u8,
    pub profile: u8,
}

/// Represents the raw data structure for firewall port filtering.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FirewallPortFilterRaw {
    pub local_port: LocalPort,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum LocalPort {
    Any(String),
    List {
        value: Vec<String>,
        #[serde(rename = "Count")]
        count: usize,
    },
}

/// Defines possible actions for a firewall rule.
/// Action determines whether to allow or block traffic.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Action {
    Allow = 1,
    Block = 0,
    NoExists = -1,
}

/// Specifies the direction of network traffic.
/// Direction indicates if the rule is for incoming or outgoing traffic.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Represents the network protocol used in the rule.
/// Protocol can be TCP, UDP, or any.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    TCP,
    UDP,
    #[serde(rename = "Any")]
    Any,
    ICMP,
}

/// Defines the local ports to which the rule applies.
/// Port can be all ports or a specific list of ports.
#[derive(Debug, Clone, PartialEq)]
pub enum Port {
    Any,
    List(Vec<PortSpec>),
}

/// Specifies individual ports or ranges.
/// PortSpec allows defining single ports or port ranges.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum PortSpec {
    /// A single port number
    Single(u16),
    /// A range from start to end
    Range { start: u16, end: u16 },
}

/// Defines the network profile for the rule.
/// Profile specifies the network location type.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Profile {
    Any,
    Domain,
    Private,
    Public,
}
