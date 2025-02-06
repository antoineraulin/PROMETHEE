mod i18n;
mod methods;
mod parser;
mod traits;
mod utils;

use advanced_auditing::{utils::update_audit_config, AUDIT_STRATEGIES};
use clap::Parser;
use cli::Args;
use colored::Colorize;
use csv::Writer;
use indicatif::{MultiProgress, ProgressBar};
use lgpo::{data_structures::LGPOS, utils::update_lgpo};
use methods::*;
use parser::parse_csv;
use rule::Rule;
use safer::{data_structures::SAFER_RULES, utils::update_safer};
use secedit::{utils::update_secedit_config, SECEDIT_CONFIG};
use std::fs::File;
use std::process::exit;
use sys_locale::get_locale;
use traits::*;
use utils::SYS_LOCALE;

fn main() {
    let args = Args::parse();

    let multi = MultiProgress::new();
    utils::setup_logging(&args, multi.clone()).expect("failed to initialize logging.");
    info!("Logging has been set up successfully.");

    info!(
        "{} v{} starting up!",
        env!("CARGO_CRATE_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    debug!("DEBUG output enabled.");
    trace!("TRACE output enabled.");

    match utils::check_admin() {
        Ok(_) => info!("Running as administrator."),
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    }

    match args.mode {
        cli::Mode::Apply {
            skip_restore_point, ..
        } => match skip_restore_point {
            true => warn!("Skipping system restore point creation."),
            false => match utils::create_system_restore_point(&format!(
                "{}-Startup",
                env!("CARGO_CRATE_NAME")
            )) {
                Ok(_) => info!("Successfully created system restore point."),
                Err(e) => {
                    warn!("{}", e);
                    exit(1);
                }
            },
        },
        _ => {}
    }

    // Get system locale
    match SYS_LOCALE.set(get_locale().unwrap_or_else(|| String::from("en-US"))) {
        Ok(_) => info!(
            "System locale set to: {}",
            SYS_LOCALE.get().as_ref().unwrap()
        ),
        Err(e) => {
            warn!("Failed to set system locale: {}", e);
            exit(1);
        }
    }

    let mut backup_store: Vec<Rule> = Vec::new();
    let mut audit_store: Vec<(String, String, bool)> = Vec::new();

    let mut scores: (u32, u32) = (0, 0);

    debug!("Parsing CSV file: {:?}", args.config_location());

    match parse_csv(args.config_location()) {
        Ok(rules) => {
            info!("Successfully parsed CSV file with {} rules.", rules.len());

            let pg = multi.add(ProgressBar::new(rules.len() as u64));

            let mut category = String::new();

            for rule in rules {
                if rule.category != category {
                    info!("\n\nStarting category: {}\n", rule.category);
                    category = rule.category.clone();
                }

                match args.mode {
                    cli::Mode::Backup { .. } => {
                        debug!("Saving current state for rule: {:?}", rule);
                        match rule.backup() {
                            Ok(backed_up_rule) => {
                                backup_store.push(backed_up_rule);
                                info!(
                                    "{}: {}",
                                    rule.pretty_display(),
                                    "SAVED".bold().bright_green()
                                );
                                scores.0 += 1;
                            }
                            Err(e) => {
                                warn!("Failed to backup rule: {:?}, error: {}", rule, e);
                                error!(
                                    "{}: {}",
                                    rule.pretty_display(),
                                    "BACKUP FAILED".bold().bright_red()
                                );
                                scores.1 += 1;
                            }
                        }
                    }
                    cli::Mode::Apply { .. } => {
                        debug!("Applying rule: {:?}", rule);
                        match rule.method.execute() {
                            Ok(_) => {
                                info!("{}: {}", rule.pretty_display(), "OK".bold().bright_green());
                                scores.0 += 1;
                            }
                            Err(e) => {
                                warn!(
                                    "Error applying {:?}: {}",
                                    rule,
                                    e.to_string().bold().bright_red()
                                );
                                error!(
                                    "{}: {} {}",
                                    rule.pretty_display(),
                                    "ERROR".bold().bright_red(),
                                    e.to_string().bold().on_red()
                                );
                                scores.1 += 1;
                            }
                        }
                    }
                    cli::Mode::Audit { .. } => {
                        debug!("Auditing rule: {:?}", rule);
                        match rule.backup() {
                            Ok(backed_up_rule) => {
                                if backed_up_rule == rule {
                                    info!(
                                        "{}: {}",
                                        rule.pretty_display(),
                                        "OK".bold().bright_green()
                                    );
                                    audit_store.push((rule.id.clone(), rule.name.clone(), true));
                                    scores.0 += 1;
                                } else {
                                    info!(
                                        "{}: {} {}",
                                        rule.pretty_display(),
                                        "NOK".bold().bright_red(),
                                        format!(
                                            "{}",
                                            Rule::pretty_diff(&rule, &backed_up_rule)
                                                .italic()
                                                .yellow()
                                        )
                                    );
                                    audit_store.push((rule.id.clone(), rule.name.clone(), false));
                                    scores.1 += 1;
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Error auditing {:?}: {}",
                                    rule,
                                    e.to_string().bold().bright_red()
                                );
                                audit_store.push((rule.id.clone(), rule.name.clone(), false));
                                scores.1 += 1;
                            }
                        }
                    }
                }
                pg.inc(1);
            }

            match args.mode {
                cli::Mode::Backup { output, .. } => {
                    // save the backup store to a file
                    let csv_records: Vec<parser::CsvRecord> =
                        backup_store.iter().map(|r| r.to_csv()).collect();
                    let mut writer = csv::Writer::from_path(&output).unwrap();
                    for record in csv_records {
                        writer.serialize(record).unwrap();
                    }
                    info!(
                        "Successfully saved {} rules ({} errors) to {:?}.",
                        scores.0, scores.1, output
                    );
                }
                cli::Mode::Apply { .. } => {
                    if SECEDIT_CONFIG.get().is_some() {
                        if let Err(e) = update_secedit_config() {
                            error!("Failed to update secedit config: {}", e);
                        } else {
                            debug!("Successfully updated secedit config");
                        }
                    }

                    if AUDIT_STRATEGIES.get().is_some() {
                        if let Err(e) = update_audit_config() {
                            error!("Failed to update audit strategies: {}", e);
                        } else {
                            debug!("Successfully updated audit strategies");
                        }
                    }

                    if SAFER_RULES.get().is_some() {
                        if let Err(e) = update_safer() {
                            error!("Failed to update SAFER rules: {}", e);
                        } else {
                            debug!("Successfully updated SAFER rules");
                        }
                    }

                    if LGPOS.get().is_some() {
                        if let Err(e) = update_lgpo() {
                            error!("Failed to update LGPOs: {}", e);
                        } else {
                            debug!("Successfully updated LGPOs");
                        }
                    }

                    info!(
                        "Successfully applied {} rules, with {} errors.",
                        scores.0, scores.1
                    );
                }
                cli::Mode::Audit {
                    report,
                    report_file,
                    ..
                } => {
                    if report {
                        let report_file = report_file.unwrap();
                        let file = File::create(&report_file).unwrap_or_else(|e| {
                            error!("Failed to create report file: {}", e);
                            exit(1);
                        });
                        let mut wtr = Writer::from_writer(file);

                        // Write header
                        wtr.write_record(&["Id", "Name", "Compliance Result"])
                            .unwrap();

                        // Iterate over rules and write records
                        for (id, name, compliance) in &audit_store {
                            let compliance_str = match compliance {
                                true => "OK",
                                false => "NOK",
                            };
                            wtr.write_record(&[id, name, &compliance_str.to_string()])
                                .unwrap();
                        }

                        wtr.flush().unwrap();
                        info!("Audit report saved to {:?}", report_file);
                    }

                    info!(
                        "Successfully audited {} rules : {} OK, {} NON COMPLIANT.",
                        scores.0 + scores.1,
                        scores.0,
                        scores.1
                    );
                }
            }
        }
        Err(e) => {
            error!("Error parsing CSV: {}", e);
        }
    }

    println!("\nPress Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}
