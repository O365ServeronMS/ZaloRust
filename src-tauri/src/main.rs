#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    // Batch 22 Q1: `zalors --quit` — a scriptable, GRACEFUL quit. The exit
    // itself always happens in a RUNNING instance, on the one quit path
    // the tray/window menus use (`tray::quit` -> `app.exit(0)` ->
    // `RunEvent::ExitRequested`, whose handler runs `shadow::backup::on_exit`
    // exactly like a tray quit). This process only decides whether there
    // is an instance to ask:
    //
    //   no other zalors.exe (Some(false)) -> print `zalors: not running`,
    //     exit 0, and NEVER start Tauri: the single-instance plugin only
    //     DELIVERS argv to an already-running first instance — with none,
    //     this process would become the app, which a quit must never do.
    //   probe failed (None) -> fail closed (the probe's own contract):
    //     say so, exit 1, start nothing.
    //   another one runs (Some(true)) -> straight into `run()`. The
    //     single-instance plugin's own setup then guarantees this process
    //     can never linger as a second app instance: it creates the same
    //     named mutex, sees ERROR_ALREADY_EXISTS, WM_COPYDATA-forwards
    //     this argv (`--quit` included) to the running instance's
    //     callback, and then runs `app.cleanup_before_exit();
    //     std::process::exit(0)` BEFORE `Builder::run` — no window, no
    //     tray, no pipeline is ever built here (tauri-plugin-single-
    //     instance 2.5.5, platform_impl/windows.rs). The running
    //     instance's callback classifies `--quit` first (lib.rs
    //     `second_launch_intent`) and runs that same exit path.
    //
    // Checked BEFORE the `import`/`repair` dispatch below, and the
    // Some(true) case goes straight into `run()` — a quit request is
    // never masked by other args in the same argv.
    if zalors_lib::wants_quit(&argv) {
        match zalors_lib::shadow::import_apply::zalors_running_besides(std::process::id()) {
            Some(false) => {
                // A GUI-subsystem release build has no console of its own;
                // attach the launching script's so the line below reaches
                // it (debug builds already have one; a failed attach — e.g.
                // a double-click launch — only means the print has nowhere
                // to go; the exit code is still 0). `writeln!` with the
                // result dropped: a quit path must never panic on an
                // unusable stdout.
                #[cfg(windows)]
                attach_parent_console();
                {
                    use std::io::Write;
                    let _ = writeln!(std::io::stdout(), "zalors: not running");
                }
                std::process::exit(0);
            }
            // Another instance runs: straight into the app builder —
            // no CLI dispatch in between (--quit wins) — where the
            // single-instance plugin forwards `--quit` to the running
            // instance and exits this process (see the comment above).
            // `run()` only returns once the event loop has ended.
            Some(true) => {
                zalors_lib::run();
                return;
            }
            None => {
                #[cfg(windows)]
                attach_parent_console();
                {
                    use std::io::Write;
                    let _ = writeln!(
                        std::io::stdout(),
                        "zalors: quit: running-instance check failed"
                    );
                }
                std::process::exit(1);
            }
        }
    }

    // P2/2.0 (audit M2-5): `zalors import …` dispatches to the shadow
    // import CLI and exits BEFORE Tauri starts — an import launch must
    // never become a second app instance. The lib crate is `zalors_lib`
    // ([lib] name in Cargo.toml) with `pub mod shadow` → `pub mod cli`.
    if argv.get(1).map(String::as_str) == Some("import") {
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
        let code = zalors_lib::shadow::cli::main(&argv[2..]);
        std::process::exit(code);
    }

    // Batch 20 (audit T8): `zalors repair …` dispatches the same way —
    // the guarded repair CLI runs before Tauri starts, attaches the
    // parent console like the import branch, and exits with the CLI's
    // code (0 ok/help · 1 runtime refusal/failure · 2 parse error).
    if argv.get(1).map(String::as_str) == Some("repair") {
        #[cfg(windows)]
        attach_parent_console();
        let code = zalors_lib::shadow::repair_cli::main(&argv[2..]);
        std::process::exit(code);
    }

    // Batch 26 M1: `zalors media …` — the read-only media SHAPE CLI.
    // It never writes and needs no process check, so it is safe to
    // run while the app is up; dispatched like `repair` (parent
    // console attached, CLI exit codes, never a second app instance).
    if argv.get(1).map(String::as_str) == Some("media") {
        #[cfg(windows)]
        attach_parent_console();
        let code = zalors_lib::shadow::media_cli::main(&argv[2..]);
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
