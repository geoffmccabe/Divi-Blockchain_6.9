//! The daemon, as a program.
//!
//! Everything it does lives in `dvxp_scan::daemon` so that a host embedding this
//! crate runs exactly the same code rather than reimplementing the loop. The
//! explorer's own binary is the same two lines.

fn main() -> std::process::ExitCode {
    dvxp_scan::run_daemon()
}
