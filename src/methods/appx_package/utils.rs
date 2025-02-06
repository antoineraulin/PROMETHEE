use std::process::Command;

use super::*;
use crate::traits::*;

/// Removes an installed AppX package by name.
///
/// # Purpose
/// This function removes a Windows AppX package that has already been installed.
///
/// # Behavior
/// It leverages PowerShell to locate and remove the specified package.
///
/// # Errors
/// Returns an error if the removal command fails.
pub fn remove_appx_package(name: &String) -> R<()> {
    trace!("Entering remove_appx_package for: {}", name);
    // We opt for a PowerShell command to reliably remove AppX packages on Windows.
    trace!("Removing installed AppX package: {}", name);
    // Remove installed package
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Get-AppxPackage -Name '{}' | Remove-AppxPackage", name),
        ])
        .output()?;
    debug!("Successfully called Remove-AppxPackage for: {}", name);

    Ok(())
}

/// Removes a provisioned AppX package by name.
///
/// # Purpose
/// This function removes a staged Windows AppX package so it is no longer provisioned for new users.
///
/// # Behavior
/// Uses PowerShell to remove a package that is staged (provisioned) on the system.
///
/// # Errors
/// Returns an error if the PowerShell command fails.
pub fn remove_provisioned_appx_package(name: &String) -> R<()> {
    trace!("Entering remove_provisioned_appx_package for: {}", name);
    // We use a separate PowerShell command to remove packages that are in a provisioned state.
    trace!("Removing provisioned AppX package: {}", name);
    // Remove provisioned package
    Command::new("powershell")
                        .args([
                            "-NoProfile",
                            "-Command",
                            &format!("Get-AppxProvisionedPackage -Online | Where-Object {{$_.DisplayName -eq '{}'}} | Remove-AppxProvisionedPackage -Online", name)
                        ])
                        .output()?;
    debug!("Provisioned package removal attempted for: {}", name);

    Ok(())
}

/// Installs an AppX package from given or default paths.
///
/// # Purpose
/// This function installs an AppX package if it is not already installed.
///
/// # Behavior
/// It tries various predefined locations or a user-provided source path to install the package.
///
/// # Errors
/// Returns an error if the package cannot be found or the installation fails.
pub fn install_appx_package(package: &AppxPackage) -> R<()> {
    trace!("Starting install_appx_package for: {}", package.name);
    // Here we attempt to locate the package in multiple possible directories to cater for different setups.
    // Try to find package file in predefined locations
    let mut package_paths = vec![
        format!("C:\\Windows\\Packages\\{}\\", package.name),
        format!("C:\\Program Files\\WindowsApps\\{}\\", package.name),
    ];

    if let Some(source) = &package.package_source {
        package_paths.insert(0, source.clone());
    }

    let mut installed = false;
    for path in package_paths {
        trace!("Attempting to install AppX package from: {}", path);
        // Try regular package installation
        let result = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Add-AppxPackage -Path '{}'", path),
            ])
            .output();

        if result.is_ok() && result?.status.success() {
            installed = true;
            break;
        }
    }

    debug!("Installation state for {}: {}", package.name, installed);

    if !installed {
        warn!("Failed to find or install package: {}", package.name);
        return Err("Package source not found or installation failed".into());
    }

    Ok(())
}

/// Provisions an AppX package so it becomes available for all new user profiles.
///
/// # Purpose
/// This function stages a Windows AppX package so that new user accounts automatically receive it.
///
/// # Behavior
/// It attempts to locate and provision the package using PowerShell commands.
///
/// # Errors
/// Returns an error if provisioning fails.
pub fn provision_appx_package(package: &AppxPackage) -> R<()> {
    trace!("Starting provision_appx_package for: {}", package.name);
    // Provisioning is distinct from installation; it ensures the package is staged for new user profiles.
    let mut package_paths = vec![
        format!("C:\\Windows\\Packages\\{}\\", package.name),
        format!("C:\\Program Files\\WindowsApps\\{}\\", package.name),
    ];

    if let Some(source) = &package.package_source {
        package_paths.insert(0, source.clone());
    }
    let mut installed = false;
    for path in package_paths {
        trace!("Attempting to provision AppX package from: {}", path);
        let result = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Add-AppxProvisionedPackage -Online -PackagePath '{}' -SkipLicense",
                    path
                ),
            ])
            .output();

        if result.is_ok() && result?.status.success() {
            installed = true;
            break;
        }
    }

    debug!("Provisioning state for {}: {}", package.name, installed);

    if !installed {
        warn!("Failed to find or install package: {}", package.name);
        return Err("Package source not found or installation failed".into());
    }

    Ok(())
}

/// Retrieves the current state of an AppX package by name.
///
/// # Purpose
/// Checks if a package is installed, staged, or absent.
///
/// # Behavior
/// Queries PowerShell for both provisioned and installed states, then infers the appropriate action.
///
/// # Errors
/// Returns an error if the PowerShell queries fail.
pub fn get_appx_package(name: String) -> R<AppxPackage> {
    trace!("Entering get_appx_package for: {}", name);
    // We check if the package is provisioned first, since that can override the regular install state.
    // check if package is staged
    let provisioned_state = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{}' }}",
                name
            ),
        ])
        .output()?;

    debug!(
        "Provisioned state query result for {}: {}",
        name,
        String::from_utf8_lossy(&provisioned_state.stdout)
    );

    // a package is considered staged if above powershell command returns something
    if !String::from_utf8_lossy(&provisioned_state.stdout)
        .trim()
        .is_empty()
    {
        return Ok(AppxPackage {
            name,
            action: Action::Stage,
            package_source: None,
        });
    }

    let regular_state = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Get-AppxPackage -Name '{}' -AllUsers | Select-Object -ExpandProperty PackageUserInformation | Select-Object -ExpandProperty InstallState", name)
            ])
            .output()?;

    debug!(
        "Regular state query result for {}: {}",
        name,
        String::from_utf8_lossy(&regular_state.stdout)
    );

    let state = match String::from_utf8_lossy(&regular_state.stdout).trim() {
        "" => Action::Remove,
        "Installed" => Action::Install,
        _ => Action::Remove,
    };

    Ok(AppxPackage {
        name,
        action: state,
        package_source: None,
    })
}
