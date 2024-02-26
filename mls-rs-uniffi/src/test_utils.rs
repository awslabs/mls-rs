use uniffi_bindgen::bindings::python;

/// Run Python code in `script`.
///
/// The script can use `import mls_rs_uniffi` to get access to the
/// Python bindings.
pub fn run_python(script: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = tempfile::TempDir::with_prefix("run-python-")?;
    let script_path = tmp_dir.path().join("script.py");
    std::fs::write(&script_path, script)?;

    python::run_script(
        tmp_dir.path().to_str().unwrap(),
        "mls-rs-uniffi",
        script_path.to_str().unwrap(),
        vec![],
        &uniffi_bindgen::bindings::RunScriptOptions::default(),
    )?;

    Ok(())
}
