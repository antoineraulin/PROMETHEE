use std::{fs::File, path::PathBuf, sync::Mutex};

use csv::{ReaderBuilder, StringRecord, WriterBuilder};
use serde::{Deserialize, Deserializer, Serializer};

use super::*;
use crate::{
    i18n::advanced_auditing::*,
    lgpo::{
        utils::{lgpo_export, lgpo_import},
        LGPOCommandArgs, LGPOCommands,
    },
    traits::*,
    utils::{find_key_for_value, read_file_as_windows_1252_utf8, write_to_windows1252, SYS_LOCALE},
};

/// Normalizes an audit CSV file to produce a list of AuditStrategy.
/// We leverage standard headers to ensure consistent deserialization across locales.
fn normalize_audit_csv(csv: &File) -> R<Vec<AuditStrategy>> {
    trace!("Normalizing audit.csv file");

    let str_csv = read_file_as_windows_1252_utf8(csv)?;

    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(str_csv.as_bytes());
    debug!("Reader: {:?}", reader);
    // Read the headers
    let headers = reader.headers()?.clone();

    debug!("Read headers: {:?}", headers);

    // Get the mapping for the system locale
    let locale = SYS_LOCALE.get().unwrap();
    let header_map = AUDIT_CSV_HEADER_I18N
        .get(locale)
        .ok_or("Unsupported locale")?;

    // Map localized headers to standard headers
    let new_headers: StringRecord = headers
        .iter()
        .map(|h| find_key_for_value(header_map, h).unwrap_or_else(|| h))
        .collect();

    debug!("Mapped headers: {:?}", new_headers);

    reader.set_headers(new_headers);

    let strategies = match reader
        .deserialize()
        .collect::<Result<Vec<AuditStrategy>, csv::Error>>()
    {
        Ok(strategies) => strategies,
        Err(e) => {
            warn!("Error deserializing audit strategies: {}", e);
            return Err(e.into());
        }
    };

    // We trace how many strategies we end up with after deserialization for diagnostic purposes.
    trace!(
        "normalize_audit_csv completed with {} strategies",
        strategies.len()
    );

    Ok(strategies)
}

/// Initializes and returns all audit strategies from the 'audit.csv' file.
/// We export GPO data first, then parse and normalize the CSV for consistency.
pub fn init_audit_strategies() -> R<Vec<AuditStrategy>> {
    trace!("Initializing audit strategies");
    // Export 'audit.csv' using 'lgpo_export'
    let audit_file = lgpo_export(
        [PathBuf::from(
            "DomainSysvol\\GPO\\Machine\\microsoft\\windows nt\\Audit\\audit.csv",
        )]
        .to_vec(),
    )?
    .remove(0);

    debug!("Exported audit.csv file: {:?}", audit_file);
    // let mut bytes = Vec::new();
    // audit_file.read_to_end(&mut bytes)?;
    // let string = encoding_rs::WINDOWS_1252.decode(&bytes).0.into_owned();
    // debug!("Read audit.csv file: {:?}", string);

    // Normalize the 'audit.csv' file
    let audit_strategies = normalize_audit_csv(&audit_file)?;

    // This debug helps us confirm the final list of strategies after initialization.
    debug!(
        "init_audit_strategies found {} strategies",
        audit_strategies.len()
    );

    debug!("Normalized audit strategies: {:?}", audit_strategies);

    Ok(audit_strategies)
}

/// Updates the audit configuration by rewriting strategies back into 'audit.csv'
/// This ensures we persist any changes made at runtime and re-import them.
pub fn update_audit_config() -> R<()> {
    let strategies = AUDIT_STRATEGIES
        .get_or_init(|| Mutex::new(init_audit_strategies().unwrap_or_default()))
        .lock()
        .map_err(|_| "Failed to lock audit strategies")?;

    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);

    for strategy in strategies.iter() {
        writer.serialize(strategy)?;
    }

    // Get the mapping for the system locale
    let locale = SYS_LOCALE.get().unwrap();
    let header_map = AUDIT_CSV_HEADER_I18N
        .get(locale)
        .ok_or("Unsupported locale")?;

    let headers: String = [
        "computer_name",
        "target",
        "sub_category",
        "guid",
        "inclusion_parameter",
        "exclusion_parameter",
        "parameter_value",
    ]
    .iter()
    .map(|h| *header_map.get(h).unwrap_or(h))
    .collect::<Vec<&str>>()
    .join(",");

    let raw_csv = String::from_utf8(writer.into_inner()?)?;

    let mut lines: Vec<&str> = raw_csv.lines().collect();
    if !lines.is_empty() {
        lines[0] = &headers;
    }
    let updated_csv = lines.join("\n");

    debug!("Updated audit.csv: {}", updated_csv.clone());

    let mut temp_file = tempfile::NamedTempFile::new()?;
    write_to_windows1252(updated_csv.clone(), temp_file.as_file_mut())?;

    // We add a trace to confirm the final CSV content length.
    trace!(
        "update_audit_config is about to import updated CSV of length {}",
        updated_csv.len()
    );

    lgpo_import((
        LGPOCommands::AdvancedAuditing,
        LGPOCommandArgs::NamedTempFile(&temp_file),
    ))?;
    debug!("Successfully imported updated audit.csv");
    Ok(())
}

/// Attempts to deserialize a string into an optional AuditParameter.
/// We rely on localized parameter mappings if necessary.
pub fn to_audit_parameter<'de, D>(deserializer: D) -> Result<Option<AuditParameter>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    debug!("Deserializing audit parameter: {}", s);

    if s.trim().is_empty() {
        debug!("Empty audit parameter");
        return Ok(None);
    }

    let locale = SYS_LOCALE.get().unwrap();
    let parameter_map = AUDIT_CSV_PARAMETERS_I18N
        .get(locale)
        .ok_or("Unsupported locale")
        .map_err(serde::de::Error::custom)?;

    let normalized = find_key_for_value(parameter_map, s).unwrap_or(s);
    debug!("Normalized audit parameter: {}", normalized);
    let audit_param = serde_plain::from_str(normalized).unwrap();

    // We debug the final outcome to quickly see if we found a matching parameter or not.
    debug!("to_audit_parameter deserialized to {:?}", audit_param);

    Ok(audit_param)
}

/// Converts an AuditParameter into its localized string representation.
/// This helps maintain correct localized strings in CSV output.
pub fn from_audit_parameter<S>(
    param: &Option<AuditParameter>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    trace!("from_audit_parameter called with {:?}", param);

    if let Some(audit_param) = param {
        let locale = SYS_LOCALE.get().unwrap();
        let parameter_map = AUDIT_CSV_PARAMETERS_I18N
            .get(locale)
            .ok_or("Unsupported locale")
            .map_err(serde::ser::Error::custom)?;

        let key = serde_plain::to_string(audit_param).map_err(serde::ser::Error::custom)?;
        match parameter_map.get(&key) {
            Some(localized) => serializer.serialize_str(localized),
            None => serializer.serialize_str(""),
        }
    } else {
        serializer.serialize_str("")
    }
}
