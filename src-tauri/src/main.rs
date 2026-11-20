#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // P2/2.0 (audit M2-5): `zalors import …` dispatches to the shadow
    // import CLI and exits BEFORE Tauri starts — an import launch must
    // never become a second app instance. The lib crate is `zalors_lib`
    // ([lib] name in Cargo.toml) with `pub mod shadow` → `pub mod cli`.
    if std::env::args().nth(1).as_deref() == Some("import") {
        // Batch 7 G4: a release build is a GUI-subsystem binary (the
        // cfg_attr above), so its stdout goes nowhere even when it was
        // launched from a terminal. Attach the PARENT console in the
        // import branch only — then `zalors import …` prints its report
        // as any CLI tool would. Debug builds already have one, and
        // failure (no parent console, e.g. a double-click launch) is
        // ignored: the import still runs, its output just has nowhere
        // to go.
        #[cfg(windows)]
        attach_parent_console();
        let args: Vec<String> = std::env::args().collect();
        let code = zalors_lib::shadow::cli::main(&args[2..]);
        std::process::exit(code);
    }
    zalors_lib::run();
}

/// `AttachConsole(ATTACH_PARENT_PROCESS)` — the one Win32 entry this
/// binary needs from the console API. The `windows` crate's
/// `Win32_System_Console` feature is NOT enabled in Cargo.toml and this
/// batch adds no crates or features, so the kernel32 import is declared
/// by hand (no more unsafe than the crate-generated binding would be).
#[cfg(windows)]
fn attach_parent_console() {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(dw_process_id: u32) -> i32;
    }
    // BOOL: nonzero on success. The result is deliberately ignored —
    // see the call site above.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}
