// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Keep broken-pipe writes local to the worker, including in foreign hosts.
pub(crate) fn block_sigpipe() -> std::io::Result<()> {
    let mut signals = nix::sys::signal::SigSet::empty();
    signals.add(nix::sys::signal::Signal::SIGPIPE);
    signals.thread_block().map_err(std::io::Error::from)
}
