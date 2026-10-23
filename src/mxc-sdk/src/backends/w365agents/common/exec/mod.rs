// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exec-bridge internals: wire framing, payloads, relay loop, and transport.

pub mod frame;
pub mod payload;
pub mod relay;
pub mod transport;

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{null_pipe_handle, ExecHandle, ExecOutcome};

use crate::w365agents_common::exec::payload::ExecStartPayload;
use crate::w365agents_common::exec::relay::run_relay_session;
use crate::w365agents_common::exec::transport::{connect_upgrade, UpgradeTarget};

/// Build the `ExecHandle` after the relay has already completed. The `waiter`
/// simply returns the captured exit code; the `terminator` is a no-op (mid-run
/// kill is delivered by the process dying → duplex close → DC kill-on-close).
///
/// The pipe handles are the framework's null sentinel, which tells the
/// dispatcher "the backend relayed I/O itself" so it skips its own relay setup.
fn assemble_handle(exit_code: i32) -> ExecHandle {
    let null = null_pipe_handle();
    ExecHandle {
        stdout: null,
        stderr: null,
        stdin: null,
        stdin_closer: None,
        waiter: Box::new(move || Ok(ExecOutcome::Exited(exit_code))),
        terminator: Box::new(|| Ok(())),
    }
}

/// Open the exec duplex to the device and run the whole relay synchronously,
/// writing to this process's own stdout/stderr and reading its stdin. Returns
/// an `ExecHandle` whose `waiter` yields the captured exit code.
pub fn run_exec(target: UpgradeTarget, start: ExecStartPayload) -> Result<ExecHandle, MxcError> {
    // Validate and encode `EXEC_START` before dialing so an oversized (>64 KiB)
    // payload fails before opening the TLS upgrade.
    let _ = start.encode()?;
    let stream = connect_upgrade(&target)?;
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let exit_code = run_relay_session(stream, start, &mut stdout, &mut stderr, std::io::stdin())?;
    Ok(assemble_handle(exit_code))
}

#[cfg(test)]
mod tests {
    use super::assemble_handle;
    use crate::mxc_common::state_aware_backend::ExecOutcome;

    #[test]
    fn assembles_a_null_pipe_handle_returning_the_exit_code() {
        let handle = assemble_handle(42);
        // Null pipe handles: the dispatcher skips its own relay setup.
        let outcome = (handle.waiter)().unwrap();
        assert_eq!(outcome, ExecOutcome::Exited(42));
        assert!((handle.terminator)().is_ok()); // no-op must not panic
    }
}
