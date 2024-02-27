/// Run sync and async Python scenarios from `test_bindings/`.
///
/// The scripts are given as identifiers (can be `None` if the sync or
/// async test variant does not exist). The identifiers which serve as
/// both the test name and as the filename inside the `test_bindings/`
/// directory.
///
/// The test script can use `import mls_rs_uniffi` to get access to
/// the Python bindings.
///
/// Auto-generated are written to `target/mls-rs-uniffi-*/`
/// directories, with one directory per scenario.
#[macro_export]
macro_rules! generate_python_tests {
    ($sync_scenario:ident, None) => {
        #[cfg(not(mls_build_async))]
        generate_python_tests!($sync_scenario);
    };

    (None, $async_scenario:ident) => {
        #[cfg(mls_build_async)]
        generate_python_tests!($async_scenario);
    };

    ($sync_scenario:ident, $async_scenario:ident) => {
        #[cfg(not(mls_build_async))]
        generate_python_tests!($sync_scenario);

        #[cfg(mls_build_async)]
        generate_python_tests!($async_scenario);
    };

    ($scenario:ident) => {
        #[test]
        fn $scenario() -> Result<(), Box<dyn std::error::Error>> {
            // This ignores any --target-dir passed to Cargo. Tests
            // still work, we just always write the temporary files to
            // target/ instead of where --target-dir tell us to write.
            let target_dir = format!("{}/../target", env!("CARGO_MANIFEST_DIR"));
            let script_path = format!(
                "{}/test_bindings/{}.py",
                env!("CARGO_MANIFEST_DIR"),
                stringify!($scenario)
            );

            uniffi_bindgen::bindings::python::run_script(
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
