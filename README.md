# PROMÉTHÉE

## Introduction

**PROMÉTHÉE** is a Windows hardening tool written in Rust, designed to apply security configurations defined in a CSV-based “rules” file.

- It can **assess** whether a system is compliant with specified hardening rules.
- It can **backup** existing Windows settings so you have a fallback if something goes wrong.
- It can **harden** the operating system by applying the rules outlined in a CSV file.

The project is inspired by tools like **HardeningKitty**, **LGPO**, and other security frameworks, but aims to be **faster**, **more efficient**, and **extensible**.

## Why “PROMÉTHÉE”?

**PROMÉTHÉE** is the French name for **Prometheus**, the Titan from Greek mythology who gifted fire (knowledge) to humanity.

- The acronym stands for **P**roactively **R**einforcing **O**ur **M**icrosoft-Windows **E**nvironments **T**hrough **H**ardening, **E**xtensible **E**valuations.
- This name embodies the project’s mission to help administrators show and assess what security an air-gapped (or off-domain) computer is configured with.

## Key Advantages Over HardeningKitty

- **Purpose-Built for Hardening**:  
   HardeningKitty’s main focus was (and still is) **assessing** compliance. It recently introduced an **“apply”** mode, but it can sometimes be error-prone due to its secondary nature. **PROMÉTHÉE**, by contrast, is built from the ground up with a focus on **applying** security configurations effectively, while providing compliance checks as a secondary feature.
- **Extensive Use of LGPO**:  
   HardeningKitty typically edits **registry keys** or uses **raw secedit** commands, and those changes are mostly visible only in raw files. **PROMÉTHÉE** extensively uses **LGPO** to directly edit Local Policies. As a result, the changes are immediately visible in **gpedit.msc**, making them much easier to review and update **manually** if needed. This approach leads to a more robust and maintainable security stance.

## Features

- **CSV-Driven Rules**: Easily define or modify security policies in a CSV file.
- **Multiple Modes**:
  - **Assess**: Check how many settings on the current system comply with your CSV-based security rules.
  - **Backup**: Save the current security configuration before applying changes.
  - **Harden**: Apply secure configurations to Windows using Rust for speed and memory safety.
- **Modular & Extensible**: You can add new methods (e.g., remove .exe files, add firewall rules, tweak registry settings, etc.) without heavy refactoring.
- **Rust-Powered**: Offers strong performance, reliability, and memory safety.

### Roadmap

- [ ] Implement rules filtering
- [ ] Add raw `registry.pol`, `GptTmpl.inf`, `audit.csv` and `lgpo.txt` files in backup


## Rules CSV format

The Rules CSV file consists of the following columns:

- `id`: Unique identifier for the rule.
- `name`: Name of the rule.
- `category`: Category for console printing purposes.
- `method`: Method to apply the rule.
- `target`: Target of the method.
- `option1`: First option parameter.
- `option2`: Second option parameter.
- `scope`: Scope of the method.
- `action`: Action to perform.
- `tags`: Tags to filter rules.

### Available Methods

For detailed information on each method, please refer to the [Wiki](https://git.araul.in/Ineo_Defense/PROMETHEE/wiki).

### Example

Here's an example of how the `rules.csv` might look:

| id  | name                                                              | category                                                     | method                   | target                                                      | option1          | option2                            | scope        | action              | tags              |
| --- | ----------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------ | ----------------------------------------------------------- | ---------------- | ---------------------------------- | ------------ | ------------------- | ----------------- |
| R01 | Disable WorkFolder-Client                                         | Installation > Features                                      | windows_optional_feature | WorkFolder-Client                                           |                  |                                    |              | enable              | feature           |
| R02 | Remove Cortana App                                                | Installation > UWP Apps                                      | appx_package             | Microsoft.Windows.Cortana                                   |                  |                                    |              | remove              | apps              |
| R03 | Enable Password Complexity                                        | Security Settings > Accounts                                 | secedit                  | PasswordComplexity                                          |                  |                                    | systemaccess | 1                   | security          |
| R04 | Configure 'audit security groups management' to Success & Failure | Advanced audit strategies configuration > Account login      | advanced_auditing        | {0CCE9237-69AE-11D9-BED3-505054503030}                      |                  |                                    |              | success_and_failure | audits            |
| R05 | Forbidding execution of 'Get Office'                              | Legitimate process control mechanisms > Software restriction | safer                    | %programfiles%\WindowsApps\Microsoft.MicrosoftOfficeHub\\\* | disallowed       | Forbidding execution of Get Office | Paths        | exists              | apps              |
| R06 | Disable the 'Allow telemetry' rule                                | Configuring GPO computer settings > Windows components       | lgpo                     | Software\Policies\Microsoft\Windows\DataCollection          | AllowTelemetry   |                                    | computer     | DWORD:0             | telemetry         |
| R07 | Disable the 'IP Support (iphlpsvc)' service                       | Services                                                     | service                  | iphlpsvc                                                    |                  |                                    |              | disabled            | services          |
| R08 | Create group 'sample_app Users'                                   | Extra > Local groups                                         | local_group              | sample_app Users                                            | S-1-5-32-544     |                                    |              | exist               | sample_app,groups |
| R09 | Create user 'sample_app tester'                                   | Extra > Local users                                          | local_user               | sample_app tester                                           | sample_app Users |                                    |              | exist               | sample_app,users  |
