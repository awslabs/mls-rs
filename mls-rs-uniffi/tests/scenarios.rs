/// Run sync and async Python scenarios.
///
/// The Python scripts are given as identifiers, relative to this
/// file. They can be `None` if the sync or async test variant does
/// not exist.
///
/// The test script can use `import mls_rs_uniffi` to get access to
/// the Python bindings.
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
            let target_dir = env!("CARGO_TARGET_TMPDIR");
            let script_path = format!("tests/{}.py", stringify!($scenario));
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

generate_python_tests!(
    generate_signature_keypair_sync,
    generate_signature_keypair_async
);
generate_python_tests!(client_config_default_sync, client_config_default_async);
generate_python_tests!(custom_storage_sync, None);
generate_python_tests!(simple_scenario_sync, simple_scenario_async);
generate_python_tests!(ratchet_tree_sync, ratchet_tree_async);
generate_python_tests!(roster_update_sync, None);
