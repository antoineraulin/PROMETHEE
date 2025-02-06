use crate::lgpo::{self, LocalGroupPolicyObject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{LazyLock, Mutex, OnceLock},
};
use windows::core::GUID;

#[derive(Debug, Clone)]
pub struct SoftwareRestrictionPolicy {
    pub target: Target,
    pub security_level: SecurityLevel,
    pub rule_type: RuleType,
    pub description: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub lgpo_guid: Option<GUID>,
    pub state: State,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum Target {
    Path(PathBuf),
    UrlZone(UrlZones),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    Disallowed = 0,
    BasicUser = 131072,
    Unrestricted = 262144,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum RuleType {
    Paths,
    Hashes,
    UrlZones,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum UrlZones {
    Internet = 3,
    LocalIntranet = 1,
    LocalMachine = 0,
    TrustedSites = 2,
    RestrictedSites = 4,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Exists,
    NotExists,
}

pub static SAFER_RULES: OnceLock<Mutex<Vec<SoftwareRestrictionPolicy>>> = OnceLock::new();

pub static SAFER_MINIMAL_REGISTRY_KEYS: LazyLock<Vec<LocalGroupPolicyObject>> = LazyLock::new(
    || {
        vec![
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates".to_string(),
            value_name: "*".to_string(),
            action: lgpo::Action::CreateKey,
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\CRLs".to_string(),
            value_name: "*".to_string(),
            action: lgpo::Action::CreateKey,
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\CTLs".to_string(),
            value_name: "*".to_string(),
            action: lgpo::Action::CreateKey,
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\SystemCertificates\\TrustedPublisher\\Certificates".to_string(),
            value_name: "*".to_string(),
            action: lgpo::Action::CreateKey,
        },LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\SystemCertificates\\TrustedPublisher\\CRLs".to_string(),
            value_name: "*".to_string(),
            action: lgpo::Action::CreateKey,
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\SystemCertificates\\TrustedPublisher\\CTLs".to_string(),
            value_name: "*".to_string(),
            action: lgpo::Action::CreateKey,
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers".to_string(),
            value_name: "DefaultLevel".to_string(),
            action: lgpo::Action::Dword(262144),
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers".to_string(),
            value_name: "TransparentEnabled".to_string(),
            action: lgpo::Action::Dword(1),
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers".to_string(),
            value_name: "PolicyScope".to_string(),
            action: lgpo::Action::Dword(0),
        },
        LocalGroupPolicyObject {
            configuration: lgpo::Configuration::Computer,
            registry_key: "Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers".to_string(),
            value_name: "ExecutableTypes".to_string(),
            action: lgpo::Action::MultiSz(vec!["ADE","ADP","BAS","BAT","CHM","CMD","COM","CPL","CRT","EXE","HLP","HTA","INF","INS","ISP","LNK","MDB","MDE","MSC","MSI","MSP","MST","OCX","PCD","PIF","REG","SCR","SHS","URL","VB","WSC"].iter().map(|s| s.to_string()).collect()),
        },
    ]
    },
);
