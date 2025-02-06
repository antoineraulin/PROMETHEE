use crate::traits::*;
use chrono::{DateTime, Utc};
use cli::Args;
use encoding_rs::WINDOWS_1252;
use fern::colors::{Color, ColoredLevelConfig};
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::sync::OnceLock;
use std::{io, time::SystemTime};
use widestring::Utf16String;
use windows::{core::GUID, Win32::System::Com::CoCreateGuid};
use windows_elevate::check_elevated;
use winsafe::co::REG_OPTION;
use winsafe::prelude::advapi_Hkey;
use winsafe::{RegistryValue, HKEY};

pub static SYS_LOCALE: OnceLock<String> = OnceLock::new();

pub fn setup_logging(args: &Args, multi: MultiProgress) -> Result<(), fern::InitError> {
    let mut base_config = fern::Dispatch::new();

    base_config = match args.verbosity() {
        i8::MIN..=-3 => {
            // Super Quiet™
            base_config.level(log::LevelFilter::Off)
        }
        -2 => {
            // Quiet
            base_config.level(log::LevelFilter::Error)
        }
        -1 => {
            // Normal Quiet
            base_config.level(log::LevelFilter::Warn)
        }
        0 => {
            // Normal
            base_config
                .level(log::LevelFilter::Info)
                .filter(|metadata| {
                    // Reject messages with the `Warn` log level.
                    metadata.level() != log::LevelFilter::Warn
                })
        }
        1 => {
            // Verbose
            base_config.level(log::LevelFilter::Debug)
        }
        2..=i8::MAX => {
            // Very Verbose
            base_config.level(log::LevelFilter::Trace)
        }
    };

    let colors = ColoredLevelConfig::new()
        // use builder methods
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red);

    if args.log {
        // Separate file config so we can include year, month and day in file logs
        let file_config = fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "[{} {} {}] {}",
                    humantime::format_rfc3339_seconds(SystemTime::now()),
                    record.level(),
                    record.target(),
                    message
                ))
            })
            .chain(fern::log_file(args.log_file.clone().unwrap())?);

        base_config = base_config.chain(file_config);
    }

    let stdout_config = fern::Dispatch::new()
        .format(move |out, message, record| {
            // special format for debug messages coming from our own crate.
            if record.level() > log::LevelFilter::Info {
                out.finish(format_args!(
                    "[{} {} {}] {}",
                    humantime::format_rfc3339_seconds(SystemTime::now()),
                    colors.color(record.level()),
                    record.target(),
                    message
                ))
            } else {
                out.finish(format_args!(
                    "[{} {}]: {}",
                    humantime::format_rfc3339_seconds(SystemTime::now()),
                    colors.color(record.level()),
                    message
                ))
            }
        })
        .chain(io::stdout());

    base_config = base_config.chain(stdout_config);

    let (max_level, log) = base_config.into_log();

    LogWrapper::new(multi, log).try_init()?;

    log::set_max_level(max_level);

    // base_config
    //     .chain(stdout_config)
    //     .apply()?;

    if args.log {
        info!("Logging to file {:?}", args.log_file.clone().unwrap());
    }

    Ok(())
}

pub fn create_system_restore_point(description: &str) -> R<()> {
    info!("Creating a system restore point");

    debug!("Enabling System Protection on system drive");
    let enable_output = Command::new("powershell")
        .args(&["-Command", "Enable-ComputerRestore -Drive $Env:SystemDrive"])
        .output()?;

    if !enable_output.status.success() {
        let error = String::from_utf8_lossy(&enable_output.stderr);
        warn!("Failed to enable system restore: {}", error);
        return Err(format!("Failed to enable system restore: {}", error).into());
    }

    debug!("Creating restore point with description: {}", description);
    let create_output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS'",
                description
            ),
        ])
        .output()?;

    if create_output.status.success() {
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&create_output.stderr);
        warn!("Creating a system restore point failed: {}", error);
        Err("Failed to create system restore point. Consider using skip option.".into())
    }
}

pub fn check_admin() -> R<()> {
    if !check_elevated()? {
        return Err("Not running as admin.".into());
    }
    Ok(())
}

pub fn read_file_as_utf16_utf8(mut file: &File) -> R<String> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    let u16_vec: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    let content = Utf16String::from_vec(u16_vec);
    let mut utf8_string = content?.to_string();

    // Remove leading BOM if present
    if utf8_string.starts_with('\u{FEFF}') {
        utf8_string = utf8_string.trim_start_matches('\u{FEFF}').to_string();
    }

    // Replace "\r\n" with "\n"
    utf8_string = utf8_string.replace("\r\n", "\n");

    Ok(utf8_string)
}

pub fn read_file_as_windows_1252_utf8(mut file: &File) -> R<String> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let string = encoding_rs::WINDOWS_1252.decode(&bytes).0.into_owned();
    Ok(string)
}

pub fn write_to_utf16(input: String, output_file: &mut File) -> R<()> {
    // let crlf_input = input.replace("\n", "\r\n");
    let utf16_data: Vec<u16> = input.encode_utf16().collect();
    let mut utf16_bytes = Vec::with_capacity(utf16_data.len() * 2);

    for code_unit in utf16_data {
        utf16_bytes.extend_from_slice(&code_unit.to_le_bytes());
    }

    let bom = [0xFF, 0xFE]; // UTF-16LE Byte Order Mark
    output_file.write_all(&bom)?;
    output_file.write_all(&utf16_bytes)?;

    Ok(())
}

pub fn write_to_windows1252(input: String, output_file: &mut File) -> R<()> {
    let crlf_input = input.replace("\n", "\r\n");
    let (encoded, _, _) = WINDOWS_1252.encode(&crlf_input);
    output_file.write_all(&encoded)?;

    Ok(())
}

pub fn find_key_for_value<'a>(map: &'a phf::Map<&'a str, &'a str>, value: &str) -> Option<&'a str> {
    map.entries().find(|&(_, &v)| v == value).map(|(&k, _)| k)
}

const WINDOWS_FILETIME_EPOCH_DIFF: u64 = 11_644_473_600; // Difference in seconds between 1601 and 1970
const HUNDRED_NANOSECONDS: u64 = 10_000_000;

/// Converts a Windows filetime to a Unix epoch timestamp
pub fn filetime_to_epoch(filetime: u64) -> i64 {
    ((filetime / HUNDRED_NANOSECONDS) - WINDOWS_FILETIME_EPOCH_DIFF) as i64
}

pub fn datetime_to_filetime(dt: DateTime<Utc>) -> u128 {
    let timestamp = dt.timestamp() as u64;
    let seconds_since_windows_epoch = timestamp + WINDOWS_FILETIME_EPOCH_DIFF;
    let whole_seconds_in_100ns = (seconds_since_windows_epoch * HUNDRED_NANOSECONDS) as u128;
    let fractional_intervals = (dt.timestamp_subsec_nanos() as u128) / 100;
    whole_seconds_in_100ns + fractional_intervals
}

pub fn gen_guid() -> R<GUID> {
    unsafe { CoCreateGuid() }.map_err(|e| e.into())
}

pub fn read_registry(hive: HKEY, path: &str, value_name: &str) -> R<RegistryValue> {
    let hkey = hive.RegOpenKeyEx(Some(path), REG_OPTION::default(), winsafe::co::KEY::READ)?;
    hkey.RegQueryValueEx(Some(value_name)).map_err(|e| e.into())
}
