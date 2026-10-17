//! The release version lives in `../pyproject.toml`, as it did for the
//! Python package (`__version__` was read from there too), so a release
//! bumps one file. It is exported as `GATEKEEPER_VERSION`.

fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../pyproject.toml");
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(path).expect("pyproject.toml next to rust/");
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("version = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("pyproject.toml has a version line");
    println!("cargo:rustc-env=GATEKEEPER_VERSION={version}");
}
