use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version,about, long_about = None)]
pub struct Args {
    /// The mode to run the program in
    #[command(subcommand)]
    pub mode: Mode,

    /// Increase verbosity level. Use `-v` for debug, `-vv` and `-vv` for trace.
    #[arg(short, action = clap::ArgAction::Count, global = true, conflicts_with = "quiet")]
    pub verbose: u8,

    /// Decrease verbosity level. Use `-q` for warning, `-qq` for error, `-qqq` for Super Quiet™ (Off).
    #[arg(short, action = clap::ArgAction::Count, global = true, conflicts_with = "verbose")]
    pub quiet: u8,

    /// Log all output to a file.
    ///
    #[arg(short,long, global = true, requires = "log_file", action = clap::ArgAction::SetTrue)]
    pub log: bool,

    /// The location to save the log file.
    #[arg(long, global = true, requires = "log", value_parser=clap::value_parser!(PathBuf))]
    pub log_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Mode {
    /// hardens the system according to rules found in the CSV file.
    Apply {
        /// CSV config file location
        #[arg(short, long)]
        config: PathBuf,
        /// do not create a System Restore Point.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        skip_restore_point: bool,
    },
    /// creates a backup of the system according to rules found in the CSV file
    /// and stores it in a backup CSV file.
    /// The backup file can be used to restore the system to its previous state.
    Backup {
        /// CSV config file location
        #[arg(short, long)]
        config: PathBuf,
        /// The location to save the backup file.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// assesses the system's security configuration according to rules found in the CSV file
    /// and reports any deviations from the expected state.
    /// An overall score is calculated based on the number of deviations found.
    Audit {
        /// CSV config file location
        #[arg(short, long, value_parser=clap::value_parser!(PathBuf))]
        config: PathBuf,

        /// If set, the program will generate a report CSV file.
        #[arg(long, action = clap::ArgAction::SetTrue, requires = "report_file")]
        report: bool,

        /// The location to save the audit report.
        #[arg(long, value_parser=clap::value_parser!(PathBuf), requires = "report")]
        report_file: Option<PathBuf>,
    },
}

impl Args {
    pub fn verbosity(&self) -> i8 {
        self.verbose as i8 - self.quiet as i8
    }

    pub fn config_location(&self) -> PathBuf {
        match &self.mode {
            Mode::Apply { config, .. } => config.clone(),
            Mode::Backup { config, .. } => config.clone(),
            Mode::Audit { config, .. } => config.clone(),
        }
    }
}
