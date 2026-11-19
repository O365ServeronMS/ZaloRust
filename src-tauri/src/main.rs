#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // P2/2.0 (audit M2-5): `zalors import …` dispatches to the shadow
    // import CLI and exits BEFORE Tauri starts — an import launch must
    // never become a second app instance. The lib crate is `zalors_lib`
    // ([lib] name in Cargo.toml) with `pub mod shadow` → `pub mod cli`.
    if std::env::args().nth(1).as_deref() == Some("import") {
        let args: Vec<String> = std::env::args().collect();
        let code = zalors_lib::shadow::cli::main(&args[2..]);
        std::process::exit(code);
    }
    zalors_lib::run();
}
