// This script should not run on any platform besides macOS, but making the whole file conditional
// results in `cargo` complaining about there being no `main()` method in build.rs.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    swift::configure();
    swift::link_package("cryptokit-bridge", "./cryptokit-bridge/");
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod swift {
    use serde::Deserialize;
    use std::{env, process::Command};

    #[derive(Debug, Deserialize)]
    struct SwiftTargetInfo {
        #[serde(rename = "unversionedTriple")]
        pub unversioned_triple: String,
        #[serde(rename = "librariesRequireRPath")]
        pub libraries_require_rpath: bool,
    }

    #[derive(Debug, Deserialize)]
    struct SwiftPaths {
        #[serde(rename = "runtimeLibraryPaths")]
        pub runtime_library_paths: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct SwiftTarget {
        pub target: SwiftTargetInfo,
        pub paths: SwiftPaths,
    }

    fn get_target_info() -> SwiftTarget {
        let swift_target_info_str = Command::new("swift")
            .args(["-print-target-info"])
            .output()
            .unwrap()
            .stdout;

        serde_json::from_slice(&swift_target_info_str).unwrap()
    }

    pub fn configure() {
        let swift_target_info = get_target_info();
        if swift_target_info.target.libraries_require_rpath {
            panic!("Libraries require RPath! Change minimum MacOS value to fix.")
        }

        swift_target_info
            .paths
            .runtime_library_paths
            .iter()
            .for_each(|path| {
                println!("cargo:rustc-link-search=native={}", path);
            });
    }

    pub fn link_package(package_name: &str, package_root: &str) {
        let profile = env::var("PROFILE").unwrap();

        if !Command::new("swift")
            .args(["build", "-c", &profile])
            .current_dir(package_root)
            .status()
            .unwrap()
            .success()
        {
            panic!("Failed to compile swift package {}", package_name);
        }

        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let swift_target_info = get_target_info();
        println!(
            "cargo:rustc-link-search=native={}/{}.build/{}/{}",
            manifest_dir, package_root, swift_target_info.target.unversioned_triple, profile
        );
        println!("cargo:rustc-link-lib=static={}", package_name);
    }
}
