// These tests are only enabled on Linux and macOS because they don't
// run on the Windows runner in GitHub's CI. See #133.
#![cfg(unix)]

use anyhow::Context;
use std::path::{Path, PathBuf};

struct MavenArtifact {
    group_id: String,
    artifact_id: String,
    version: String,
}

impl MavenArtifact {
    fn new(group_id: &str, artifact_id: &str, version: &str) -> Self {
        Self {
            group_id: String::from(group_id),
            artifact_id: String::from(artifact_id),
            version: String::from(version),
        }
    }

    fn download(&self) -> anyhow::Result<PathBuf> {
        let MavenArtifact {
            group_id,
            artifact_id,
            version,
        } = self;
        let output_dir = env!("CARGO_TARGET_TMPDIR");
        let jar_path = format!("{artifact_id}-{version}.jar");
        let download_path = Path::new(output_dir).join(jar_path);

        if download_path.exists() {
            eprintln!("Found {}, skipping Maven download", download_path.display());
            return Ok(download_path);
        }

        eprintln!("Downloading {} using Maven", download_path.display());
        let exit_status = std::process::Command::new("mvn")
            .arg("--no-transfer-progress")
            .arg("dependency:copy")
            .arg(format!("-Dartifact={group_id}:{artifact_id}:{version}"))
            .arg(format!("-DoutputDirectory={output_dir}"))
            .status()
            .context("running `mvn` failed")?;
        if !exit_status.success() {
            anyhow::bail!("Error while running mvn!");
        }

        Ok(download_path)
    }
}

/// Download and configure Kotlin test dependencies.
///
/// This will download the Kotlin test dependencies to
/// `$CARGO_TARGET_TMPDIR` and globally update the `$CLASSPATH`
/// environment variable to point to them.
fn configure_kotlin_env() -> anyhow::Result<()> {
    let deps = [
        MavenArtifact::new("net.java.dev.jna", "jna", "5.14.0"),
        MavenArtifact::new("org.jetbrains.kotlin", "kotlin-test", "1.9.23"),
    ];

    let classpath = std::env::var("CLASSPATH").unwrap_or_default();
    let mut classpaths = std::env::split_paths(&classpath).collect::<Vec<_>>();
    for dep in deps {
        let dep_path = dep.download()?;
        if !classpaths.contains(&dep_path) {
            classpaths.push(dep_path);
        }
    }
    std::env::set_var("CLASSPATH", std::env::join_paths(classpaths)?);
    Ok(())
}

macro_rules! generate_kotlin_tests {
    ($sync_scenario:ident, None) => {
        #[cfg(not(mls_build_async))]
        generate_kotlin_tests!($sync_scenario);
    };

    (None, $async_scenario:ident) => {
        #[cfg(mls_build_async)]
        generate_kotlin_tests!($async_scenario);
    };

    ($sync_scenario:ident, $async_scenario:ident) => {
        #[cfg(not(mls_build_async))]
        generate_kotlin_tests!($sync_scenario);

        #[cfg(mls_build_async)]
        generate_kotlin_tests!($async_scenario);
    };

    ($scenario:ident) => {
        #[test]
        fn $scenario() -> anyhow::Result<()> {
            configure_kotlin_env()?;
            let target_dir = env!("CARGO_TARGET_TMPDIR");
            let script_path = format!("tests/{}.kts", stringify!($scenario));
            uniffi_bindgen::bindings::kotlin::run_script(
                &target_dir,
                "mls-rs-uniffi",
                &script_path,
                vec![],
                &uniffi_bindgen::bindings::RunScriptOptions::default(),
            )
            .map_err(Into::into)
        }
    };
}

generate_kotlin_tests!(simple_scenario_sync, None);
