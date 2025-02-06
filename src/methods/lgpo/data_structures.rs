use std::{
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tempfile::NamedTempFile;

use super::utils::*;

////////////////////////////////////////////////////////////////
// LGPO method data structures
////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LocalGroupPolicyObject {
    pub configuration: Configuration,
    pub registry_key: String,
    pub value_name: String,
    pub action: Action,
}

pub static LGPOS: OnceLock<Mutex<Vec<LocalGroupPolicyObject>>> = OnceLock::new();

////////////////////////////////////////////////////////////////
// Utils data structures
////////////////////////////////////////////////////////////////

pub enum LGPOCommands {
    /// Represents the security template command for LGPO.exe
    SecurityTemplate,
    /// Represents the Advanced Auditing command for LGPO.exe
    AdvancedAuditing,
    /// Represents the LGPO Text command for LGPO.exe
    LGPOText,
}

pub enum LGPOCommandArgs<'a> {
    /// Argument type for a file path
    PathBuf(PathBuf),
    /// Argument type for a reference to a named temporary file
    NamedTempFile(&'a NamedTempFile),
}

/// A tuple representing an LGPO command and its associated argument
pub type LGPOCommand<'a> = (LGPOCommands, LGPOCommandArgs<'a>);

////////////////////////////////////////////////////////////////
// LGPO text data structures
////////////////////////////////////////////////////////////////

/// [Configuration] specifies whether the setting is for Computer Configuration, User Configuration, or an MLGPO User Configuration.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Configuration {
    /// Computer Configuration
    Computer,
    /// System-wide User Configuration
    User,
    /// MLGPO User Configuration for Administrators
    UserAdministrators,
    /// MLGPO User Configuration for Non-Administrators
    UserNonAdministrators,
    /// MLGPO User Configuration for the named local account
    UserNamed(String),
}

/// [Action] specifies the action to take for a setting
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Action {
    ///  Deletes the value (reverting a policy to "not configured").
    /// This inserts a command into the  `registry.pol` file that deletes the named value each time policy is re-applied
    Delete,
    /// Sets the value to a _REG_DWORD_ value n. E.g. `DWORD:1`.
    /// Values can be specified in hexadecimal by prepending `0x`; e.g. `DWORD:0x1000`
    Dword(u64),
    /// Sets the value to a _REG_QWORD_ value n. E.g. `QWORD:1`.
    /// Values can be specified in hexadecimal by prepending `0x`; e.g. `QWORD:0x1000`
    Qword(u128),
    /// Sets the value to a _REG_SZ_ (text) value text. E.g. `SZ:Authorized users only!`
    Sz(String),
    /// Sets the value to a _REG_EXPAND_SZ_ (expandable text) value text. E.g. `EXSZ:%USERPROFILE%\Desktop`
    ExSz(String),
    /// Sets a multi-string value. Use the character sequence `\0` to separate multiple strings. Example: `MULTISZ:One\0Two\0Three`
    MultiSz(Vec<String>),
    /// Sets a binary value. Use comma-separated, two-digit hex values on a single line. Example: `BINARY:00,ff,01,fe,02,fd,03,fc`
    Binary(Vec<u8>),
    /// Create the key, but do not create any values. (Use `*` on the Value Name line.)
    CreateKey,
    /// Delete all values from the registry key. (Use `*` on the Value Name line.)
    DeleteAllValues,
    /// Deletes one or more subkeys from the named Registry Key. The Value Name line is a semicolon-delimited list of subkeys to delete.
    DeleteKeys(Vec<String>),
    /// Removes the named key and any commands associated with the key
    /// from policy entirely. Note that all other commands (including the
    /// [Action::Delete] command) each insert a command into the policy file. [Action::Clear]
    /// deletes commands associated with a key, as well as the key’s values
    /// and subkeys, from the policy file. The CLEAR has effect only when
    /// used with the /t command-line switch.
    Clear,
}

////////////////////////////////////////////////////////////////
// LGPO text data structures implementation
////////////////////////////////////////////////////////////////

impl<'de> Deserialize<'de> for Configuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s_trim = s.trim();

        let (key, value) = s_trim.split_once(':').unwrap_or((s_trim, ""));

        match key.to_ascii_uppercase().as_str() {
            "COMPUTER" => Ok(Configuration::Computer),
            "USER" => match value {
                "ADMINISTRATORS" => Ok(Configuration::UserAdministrators),
                "NON-ADMINISTRATORS" => Ok(Configuration::UserNonAdministrators),
                _ if value.is_empty() => Ok(Configuration::User),
                _ => Ok(Configuration::UserNamed(value.to_string())),
            },
            _ => Err(serde::de::Error::custom(format!(
                "Invalid configuration line: {}",
                s_trim
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s_trim = s.trim();

        let (key, value) = s_trim.split_once(':').unwrap_or((s_trim, ""));

        match key.to_ascii_uppercase().as_str() {
            "DELETE" => Ok(Action::Delete),
            "CREATEKEY" => Ok(Action::CreateKey),
            "DELETEALLVALUES" => Ok(Action::DeleteAllValues),
            "DELETEKEYS" => Ok(Action::DeleteKeys(Vec::new())),
            "CLEAR" => Ok(Action::Clear),
            "DWORD" => {
                let value = parse_number(value).map_err(serde::de::Error::custom)?;
                Ok(Action::Dword(value))
            }
            "QWORD" => {
                let value = parse_qword_number(value).map_err(serde::de::Error::custom)?;
                Ok(Action::Qword(value))
            }
            "SZ" => Ok(Action::Sz(unescape_string(value))),
            "EXSZ" => Ok(Action::ExSz(unescape_string(value))),
            "MULTISZ" => {
                let parts: Vec<String> = unescape_string(value)
                    .split("\\0")
                    .map(|s| s.to_string())
                    .collect();
                Ok(Action::MultiSz(parts))
            }
            "BINARY" => {
                let bytes_res: Result<Vec<u8>, _> = value
                    .split(',')
                    .map(|hex| u8::from_str_radix(hex.trim(), 16))
                    .collect();
                match bytes_res {
                    Ok(bytes) => Ok(Action::Binary(bytes)),
                    Err(_) => Err(serde::de::Error::custom(format!(
                        "Invalid binary data in action: {}",
                        s
                    ))),
                }
            }
            _ => Err(serde::de::Error::custom(format!(
                "Invalid action line: {}",
                s_trim
            ))),
        }
    }
}

impl Serialize for Configuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = match self {
            Configuration::Computer => "Computer".to_string(),
            Configuration::User => "User".to_string(),
            Configuration::UserAdministrators => "User:Administrators".to_string(),
            Configuration::UserNonAdministrators => "User:Non-Administrators".to_string(),
            Configuration::UserNamed(name) => format!("User:{}", name),
        };
        serializer.serialize_str(&str)
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = match self {
            Action::Delete => "DELETE".to_string(),
            Action::Dword(n) => format!("DWORD:{}", n),
            Action::Qword(n) => format!("QWORD:{}", n),
            Action::Sz(s) => format!("SZ:{}", s),
            Action::ExSz(s) => format!("EXSZ:{}", s),
            Action::MultiSz(values) => format!("MULTISZ:{}", values.join("\\0")),
            Action::Binary(bytes) => {
                let hex: Vec<String> = bytes.iter().map(|x| format!("{:02x}", x)).collect();
                format!("BINARY:{}", hex.join(","))
            }
            Action::CreateKey => "CREATEKEY".to_string(),
            Action::DeleteAllValues => "DELETEALLVALUES".to_string(),
            Action::DeleteKeys(keys) => format!("DELETEKEYS:{}", keys.join(";")),
            Action::Clear => "CLEAR".to_string(),
        };

        serializer.serialize_str(&str)
    }
}
