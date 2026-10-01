//! Resolve the running app's registered MSI before uninstall.

use std::path::Path;
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    MsiEnumRelatedProductsW, MsiGetProductInfoW,
};
use windows::core::{PCWSTR, PWSTR, w};

#[derive(Debug)]
struct Product {
    code: String,
    location: String,
}

fn normalized_directory(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn select_product(products: &[Product], install_dir: &str) -> Result<Option<String>, String> {
    select_product_with_policy(products, install_dir, true)
}

fn select_product_with_policy(
    products: &[Product],
    install_dir: &str,
    allow_missing_location: bool,
) -> Result<Option<String>, String> {
    let directory = normalized_directory(install_dir);
    let matches: Vec<_> = products
        .iter()
        .filter(|product| {
            !product.location.is_empty() && normalized_directory(&product.location) == directory
        })
        .collect();
    if matches.len() == 1 {
        return Ok(Some(matches[0].code.clone()));
    }
    if products.is_empty() {
        return Ok(None);
    }
    // Older packages may not publish InstallLocation. Only an unambiguous
    // member of Desktop's upgrade family is eligible for this fallback.
    if allow_missing_location && products.len() == 1 && products[0].location.is_empty() {
        return Ok(Some(products[0].code.clone()));
    }
    Err("Could not identify this SwiftTunnel installation. Open Windows Settings > Apps to select the installation to remove.".to_string())
}

pub fn desktop_product_code(install_dir: &Path) -> Result<Option<String>, String> {
    // Same family on x64 and ARM64, distinct from the standalone Lite product.
    product_code(
        install_dir,
        w!("{E8A8D9AE-1DDB-53D0-BCF4-8268BDDC947D}"),
        true,
    )
}

pub fn lite_product_code(install_dir: &Path) -> Result<Option<String>, String> {
    // Bundled Lite can coexist with standalone Lite. Missing location is not
    // sufficient evidence that a standalone product owns this executable.
    product_code(
        install_dir,
        w!("{9C4E2B77-5A81-4F36-B0D9-1E6A83C7F520}"),
        false,
    )
}

fn product_code(
    install_dir: &Path,
    upgrade_code: PCWSTR,
    allow_missing_location: bool,
) -> Result<Option<String>, String> {
    let mut products = Vec::new();
    for index in 0..128 {
        let mut code = [0u16; 39];
        let status =
            unsafe { MsiEnumRelatedProductsW(upgrade_code, None, index, PWSTR(code.as_mut_ptr())) };
        if status == ERROR_NO_MORE_ITEMS.0 {
            return if allow_missing_location {
                select_product(&products, &install_dir.to_string_lossy())
            } else {
                select_product_with_policy(&products, &install_dir.to_string_lossy(), false)
            };
        }
        if status != ERROR_SUCCESS.0 {
            return Err(format!(
                "Windows Installer could not list SwiftTunnel installations (error {status})."
            ));
        }
        let mut location = vec![0u16; 32_768];
        let mut length = location.len() as u32;
        let status = unsafe {
            MsiGetProductInfoW(
                PCWSTR(code.as_ptr()),
                w!("InstallLocation"),
                Some(PWSTR(location.as_mut_ptr())),
                Some(&mut length),
            )
        };
        if status != ERROR_SUCCESS.0 {
            return Err(format!(
                "Windows Installer could not read the installation location (error {status})."
            ));
        }
        products.push(Product {
            code: String::from_utf16_lossy(&code[..38]),
            location: String::from_utf16_lossy(&location[..length as usize]),
        });
    }
    Err("Too many SwiftTunnel installation records. Open Windows Settings > Apps to remove the selected installation.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn product(code: &str, location: &str) -> Product {
        Product {
            code: code.into(),
            location: location.into(),
        }
    }

    #[test]
    fn picks_the_running_install_instead_of_the_first_registration() {
        let products = [
            product("old", "D:\\SwiftTunnel"),
            product("current", "C:\\Program Files\\SwiftTunnel\\"),
        ];
        assert_eq!(
            select_product(&products, "c:/program files/swifttunnel")
                .unwrap()
                .as_deref(),
            Some("current")
        );
    }

    #[test]
    fn no_product_and_ambiguous_products_are_not_silent_success() {
        assert_eq!(select_product(&[], "C:\\SwiftTunnel").unwrap(), None);
        assert!(select_product(&[product("a", ""), product("b", "")], "C:\\SwiftTunnel").is_err());
        assert!(
            select_product(
                &[
                    product("a", "C:\\SwiftTunnel"),
                    product("b", "C:\\SwiftTunnel")
                ],
                "C:\\SwiftTunnel"
            )
            .is_err()
        );
    }

    #[test]
    fn only_missing_locations_allow_the_legacy_single_product_fallback() {
        assert_eq!(
            select_product(&[product("legacy", "")], "C:\\SwiftTunnel")
                .unwrap()
                .as_deref(),
            Some("legacy")
        );
        assert!(
            select_product(
                &[product("different", "D:\\SwiftTunnel")],
                "C:\\SwiftTunnel"
            )
            .is_err()
        );
    }

    #[test]
    fn family_matches_the_desktop_package() {
        let config = include_str!("../../swifttunnel-desktop/src-tauri/tauri.conf.json");
        assert!(
            config
                .to_ascii_uppercase()
                .contains("E8A8D9AE-1DDB-53D0-BCF4-8268BDDC947D")
        );
    }

    #[test]
    fn lite_family_matches_the_standalone_package() {
        assert!(
            include_str!("../../swifttunnel-lite/wix/product.wxs")
                .to_uppercase()
                .contains("9C4E2B77-5A81-4F36-B0D9-1E6A83C7F520")
        );
    }

    #[test]
    fn lite_requires_a_location_even_with_one_standalone_product() {
        assert!(
            select_product_with_policy(
                &[product("standalone", "")],
                "C:\\Program Files\\SwiftTunnel",
                false
            )
            .is_err()
        );
        assert!(
            select_product_with_policy(
                &[product("standalone", "C:\\Program Files\\SwiftTunnel Lite")],
                "C:\\Program Files\\SwiftTunnel",
                false
            )
            .is_err()
        );
        assert_eq!(
            select_product_with_policy(
                &[product("standalone", "C:\\Program Files\\SwiftTunnel Lite")],
                "C:\\Program Files\\SwiftTunnel Lite",
                false
            )
            .unwrap()
            .as_deref(),
            Some("standalone")
        );
    }
}
