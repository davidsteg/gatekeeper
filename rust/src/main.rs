fn main() {
    // The hidden entries (`__unpriv`, `__runas`) come first: this binary
    // re-executes itself through them, and they must run before anything
    // else -- no runtime, no threads, no config.
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    if let Some(code) = gatekeeper::privdrop::hidden_entry(&args) {
        std::process::exit(code);
    }
    // Then the CLI (`__main__.main`): the privilege drop, argument parsing
    // and the command. `serve` starts its tokio runtime itself, after the
    // drop, because capability changes are per thread.
    std::process::exit(gatekeeper::cli::main());
}
