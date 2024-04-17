// These tests are only enabled on Linux and macOS because they don't
// run on the Windows runner in GitHub's CI. See #133.
#![cfg(unix)]

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
        fn $scenario() -> Result<(), Box<dyn std::error::Error>> {
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
