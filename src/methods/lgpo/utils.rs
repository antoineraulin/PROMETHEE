use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{LockResult, Mutex, MutexGuard},
};

use std::io::Read;
use std::io::Write;

use codepage_437::{BorrowFromCp437, CP437_CONTROL};
use log::{debug, trace, warn};
use tempfile::tempdir;

use crate::{i18n::*, utils::SYS_LOCALE};
use crate::{
    lgpo::{deserialize::Deserializer, serialize::serialize_entries},
    traits::R,
};

use super::data_structures::*;

/// Exports LGPO settings to a temporary directory and returns the specified file.
///
/// This function uses `LGPO.exe` to export local group policy objects to a temporary directory.
/// It then locates the exported directory and retrieves the requested file.
///
/// # Arguments
///
/// * `sub_path` - The relative path to the specific LGPO file to retrieve.
///
/// # Returns
///
/// A `Result` containing a `File` handle to the requested file or an error if the process fails.
pub fn lgpo_export(sub_paths: Vec<PathBuf>) -> R<Vec<File>> {
    assert!(
        !sub_paths.is_empty(),
        "No sub-paths provided for LGPO export"
    );
    debug!("Starting LGPO export process");

    // Create a temporary directory for LGPO export
    let tmp_dir = tempdir()?;
    let path = tmp_dir.path();
    trace!("Temporary directory created at {:?}", path);

    // Execute LGPO.exe to export policies into the temporary directory
    std::process::Command::new("LGPO.exe")
        .args(&["/b", path.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("Failed to execute LGPO");

    // Find the exported directory created by LGPO.exe
    let exported_dir = std::fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.path().is_dir())
        .ok_or_else(|| "Failed to find exported LGPO directory")?;
    trace!("Exported LGPO directory found at {:?}", exported_dir.path());

    let mut res_files = vec![];

    // Construct the path to the requested file within the export
    for sub_path in sub_paths {
        let target_path = exported_dir.path().join(&sub_path);
        if !target_path.exists() {
            return Err(format!("Requested file {:?} does not exist", target_path).into());
        }
        debug!("Opening exported file at {:?}", target_path);

        // Open and return the requested file
        res_files.push(File::open(target_path)?);
    }
    Ok(res_files)
}

/// Imports LGPO settings based on the provided commands and their arguments.
///
/// This function builds command-line arguments for `LGPO.exe` based on the given parameters,
/// executes the command, and manages any temporary files required during the process.
///
/// # Arguments
///
/// * `params` - A vector of tuples containing `LGPOCommands` and their corresponding `LGPOCommandArgs`.
///
/// # Returns
///
/// An empty `Result` indicating success, or an error if the process fails.
pub fn lgpo_import<'a>(params: LGPOCommand<'a>) -> R<()> {
    debug!("Starting LGPO import process");

    let mut raw_args: Vec<String> = Vec::new();
    let mut files_to_delete: Vec<PathBuf> = Vec::new();

    let (cmd, arg) = params;
    match cmd {
        LGPOCommands::SecurityTemplate => {
            match arg {
                LGPOCommandArgs::NamedTempFile(file) => {
                    let path = file.path();
                    if path.exists() {
                        // Copy the security template to the expected filename
                        let tmpl_path = Path::new("GptTmpl.inf");
                        std::fs::copy(&path, tmpl_path)?;
                        trace!("Security template copied to {:?}", tmpl_path);

                        // Add arguments for importing the security template
                        raw_args.push("/s".to_owned());
                        raw_args.push(dunce::canonicalize(tmpl_path)?.to_str().unwrap().to_owned());
                        files_to_delete.push(tmpl_path.to_owned());
                    } else {
                        return Err(
                            format!("Security template file {:?} does not exist", path).into()
                        );
                    }
                }
                _ => {
                    return Err("Expected NamedTempFile for SecurityTemplate command".into());
                }
            }
        }
        LGPOCommands::AdvancedAuditing => {
            match arg {
                LGPOCommandArgs::NamedTempFile(file) => {
                    let path = file.path();
                    if path.exists() {
                        // // Copy the security template to the expected filename
                        // let tmpl_path = Path::new("GptTmpl.inf");
                        // std::fs::copy(&path, tmpl_path)?;
                        // trace!("Security template copied to {:?}", tmpl_path);

                        // // Add arguments for importing the security template
                        raw_args.push("/ac".to_owned());
                        raw_args.push(dunce::canonicalize(path)?.to_str().unwrap().to_owned());
                        // files_to_delete.push(tmpl_path.to_owned());
                    } else {
                        return Err(
                            format!("Advanced Auditing file {:?} does not exist", path).into()
                        );
                    }
                }
                _ => {
                    return Err("Expected NamedTempFile for AdvancedAuditing command".into());
                }
            }
        }
        LGPOCommands::LGPOText => {
            match arg {
                LGPOCommandArgs::NamedTempFile(file) => {
                    let path = file.path();
                    if path.exists() {
                        // Copy the LGPO text to the expected filename
                        let tmpl_path = Path::new("lgpo.txt");
                        std::fs::copy(&path, tmpl_path)?;
                        trace!("LGPO text copied to {:?}", tmpl_path);

                        // // Add arguments for importing the LGPO text
                        raw_args.push("/t".to_owned());
                        raw_args.push(dunce::canonicalize(tmpl_path)?.to_str().unwrap().to_owned());
                        // files_to_delete.push(tmpl_path.to_owned());
                    } else {
                        return Err(format!("LGPO text file {:?} does not exist", path).into());
                    }
                }
                _ => {
                    return Err("Expected NamedTempFile for LGPOText command".into());
                }
            }
        }
    }

    // Add verbosity argument to apply changes immediately
    raw_args.push("/v".to_owned());
    trace!("Executing LGPO.exe with arguments: {:?}", raw_args);

    // Execute LGPO.exe with the constructed arguments
    let output = std::process::Command::new("LGPO.exe")
        .args(&raw_args)
        .output()
        .expect("Failed to execute LGPO");

    // Log the output from LGPO.exe for debugging
    let stdout = match cmd {
        LGPOCommands::AdvancedAuditing => String::borrow_from_cp437(&output.stdout, &CP437_CONTROL),
        LGPOCommands::SecurityTemplate => encoding_rs::WINDOWS_1252
            .decode(&output.stdout)
            .0
            .to_string(),
        LGPOCommands::LGPOText => String::from_utf8(output.stdout)?,
    };
    debug!("LGPO.exe output:\n{}", stdout);

    let stderr = match cmd {
        LGPOCommands::AdvancedAuditing => String::borrow_from_cp437(&output.stderr, &CP437_CONTROL),
        LGPOCommands::SecurityTemplate => encoding_rs::WINDOWS_1252
            .decode(&output.stderr)
            .0
            .to_string(),
        LGPOCommands::LGPOText => String::from_utf8(output.stderr).unwrap_or_default(),
    };
    warn!("LGPO.exe error output:\n{}", stderr);

    // Clean up any temporary files created during the import process
    for file in files_to_delete {
        std::fs::remove_file(&file)?;
        trace!("Deleted temporary file {:?}", file);
    }

    let locale = SYS_LOCALE.get().unwrap();

    // Check LGPO.exe output for success indicator
    match cmd {
        LGPOCommands::SecurityTemplate => {
            let indicator = SECEDIT_COMMONS_I18N
                .get(locale)
                .unwrap()
                .get("done_100")
                .unwrap();
            if stdout.contains(indicator) {
                Ok(())
            } else {
                Err("Failed to import security template".into())
            }
        }
        LGPOCommands::AdvancedAuditing => {
            let indicator = AUDITPOL_COMMON_I18N
                .get(locale)
                .unwrap()
                .get("error_indicator")
                .unwrap();
            if stderr.contains(indicator) {
                Err("Failed to import advanced auditing settings".into())
            } else {
                Ok(())
            }
        }
        LGPOCommands::LGPOText => {
            if stdout.contains("POLICY SAVED.") {
                Ok(())
            } else {
                Err("Failed to import LGPO text".into())
            }
        }
    }
}

pub fn get_lgpos() -> LockResult<MutexGuard<'static, Vec<LocalGroupPolicyObject>>> {
    LGPOS
        .get_or_init(|| Mutex::new(init_lgpos().unwrap_or_default()))
        .lock()
}

pub fn init_lgpos() -> R<Vec<LocalGroupPolicyObject>> {
    trace!("Initializing LGPOs");

    let mut registry_pols = lgpo_export(vec![
        PathBuf::from("DomainSysvol\\GPO\\Machine\\registry.pol"),
        PathBuf::from("DomainSysvol\\GPO\\User\\registry.pol"),
    ])?;
    debug!("Exported registry.pol files (Computer & User)");

    // A helper closure to process a registry.pol file.
    let process_registry =
        |mut file: File, label: &str, parse_arg: &str| -> R<Vec<LocalGroupPolicyObject>> {
            let mut buff = Vec::new();
            file.read_to_end(&mut buff)
                .map_err(|e| format!("Failed to read {} registry.pol file: {}", label, e))?;
            debug!("Saved {} registry.pol to buffer: {:?}", label, buff);

            let temp_filename = format!("{}_registry.pol.temp", label);
            std::fs::write(&temp_filename, &buff).map_err(|e| {
                format!(
                    "Failed to write {} registry.pol to {}: {}",
                    label, temp_filename, e
                )
            })?;
            debug!("Wrote {} registry.pol to {}", label, temp_filename);

            let canonical_path = dunce::canonicalize(&temp_filename)?;
            let canonical_str = canonical_path.to_str().unwrap_or_default().to_string();
            debug!(
                "Executing LGPO for {} with path: {:?}",
                label, canonical_str
            );

            let output = std::process::Command::new("LGPO.exe")
                .args(&["/parse", parse_arg, &canonical_str])
                .output()
                .map_err(|e| format!("Failed to execute LGPO for {}: {}", label, e))?;
            debug!("LGPO {} parse done", label);

            std::fs::remove_file(&canonical_path)
                .map_err(|e| format!("Failed to remove temporary file {}: {}", temp_filename, e))?;
            debug!("Removed temporary file {}", temp_filename);

            let lgpo_text = String::from_utf8(output.stdout)
                .map_err(|e| format!("Invalid UTF-8 output for {}: {}", label, e))?;
            if !output.stderr.is_empty() {
                warn!(
                    "{} LGPO err: {}",
                    label,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            debug!("{} LGPO text: {}", label, lgpo_text);

            let lines = lgpo_text.lines();
            let mut de = Deserializer::new(lines.map(|line| Ok(line.to_string())));
            let parsed: Vec<LocalGroupPolicyObject> = serde::Deserialize::deserialize(&mut de)?;
            Ok(parsed)
        };

    // Assume the first file is for the computer and the second for the user.
    let computer_lgpos = process_registry(registry_pols.remove(0), "computer", "/m")?;
    let user_lgpos = process_registry(registry_pols.remove(0), "user", "/u")?;

    let mut lgpos = computer_lgpos;
    lgpos.extend(user_lgpos);
    Ok(lgpos)
}

pub fn update_lgpo() -> R<()> {
    let lgpos = LGPOS
        .get_or_init(|| Mutex::new(init_lgpos().unwrap_or_default()))
        .lock()
        .map_err(|_| "Failed to lock LGPOs")?;

    let mut buffer = Vec::new();
    serialize_entries(&mut buffer, &lgpos)?;
    let raw_lgpo_text = String::from_utf8(buffer).expect("LGPO file should be valid UTF-8");
    debug!("Serialized LGPO text: {}", raw_lgpo_text);
    let mut temp_file = tempfile::NamedTempFile::new()?;
    temp_file.write_all(raw_lgpo_text.as_bytes())?;
    lgpo_import((
        LGPOCommands::LGPOText,
        LGPOCommandArgs::NamedTempFile(&temp_file),
    ))
}

//////////////////////////////////////////////////////////////////////
// LGPO text data structures serialization and deserialization utils
//////////////////////////////////////////////////////////////////////

pub fn parse_number(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

pub fn parse_qword_number(s: &str) -> Result<u128, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u128>().map_err(|e| e.to_string())
    }
}

pub fn unescape_string(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // look at next char for escape
            if let Some(&next) = chars.peek() {
                match next {
                    'r' => {
                        result.push('\r');
                        chars.next();
                    }
                    'n' => {
                        result.push('\n');
                        chars.next();
                    }
                    '\\' => {
                        result.push('\\');
                        chars.next();
                    }
                    _ => {
                        // unknown escape, just push it
                        result.push('\\');
                    }
                }
            } else {
                // trailing backslash
                result.push('\\');
            }
        } else {
            result.push(c);
        }
    }
    result
}
