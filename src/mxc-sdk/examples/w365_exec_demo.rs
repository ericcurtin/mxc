// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Demo driver: run a command on a W365 VM via the DesktopControl.Exec
//! capability, streamed back over the RemotingInterface relay (TLS) or a
//! local/plaintext endpoint. The remote stdout/stderr are written to this
//! terminal and the process exits with the remote exit code — so it
//! screen-records cleanly. Progress lines are prefixed `[demo]` on stderr.
//!
//! This is the same engine `wxc-exec` drives (`W365AgentsRunner::exec` ->
//! `run_relay_session`); it only skips config-file plumbing and lets you point
//! at a plaintext local RemotingInterface (which `wxc-exec`'s TLS-only path
//! cannot reach) for a fully local recording.
//!
//! TLS (real / test-cluster RemotingInterface):
//!   cargo run -p mxc-sdk --features w365_agents --example w365_exec_demo -- \
//!     --host <poolId>.<regional-ri-host> --port 443 \
//!     --computer <computerId> --token <dataplane-token> \
//!     --command "hostname"
//!
//! Plaintext (local RI proxy, or directly at a loopback DesktopControl.Exec):
//!   cargo run -p mxc-sdk --features w365_agents --example w365_exec_demo -- \
//!     --host 127.0.0.1 --port 49200 --plaintext \
//!     --computer demo --token unused --command "echo hello from the VM"

use std::io::{stderr, stdin, stdout, Write};
use std::net::TcpStream;
use std::process;

use mxc_sdk::mxc_common::mxc_error::MxcError;
use mxc_sdk::w365agents_common::exec::payload::ExecStartPayload;
use mxc_sdk::w365agents_common::exec::relay::run_relay_session;
use mxc_sdk::w365agents_common::exec::transport::{
    build_upgrade_request, connect_upgrade, read_upgrade_response, UpgradeTarget,
    HANDSHAKE_TIMEOUT, READ_POLL_TIMEOUT,
};

const USAGE: &str = "\
w365_exec_demo - run a command on a W365 VM via DesktopControl.Exec

REQUIRED:
  --host <host>        dataplane host (TLS: <pool>.<regional-ri>; plaintext: e.g. 127.0.0.1)
  --computer <id>      computerId / sessionId
  --command <cmd>      command to run on the VM

OPTIONAL:
  --port <n>           default 443
  --token <tok>        dataplane bearer token (default \"unused\"; ignored by a loopback host)
  --capability <name>  default microsoft.mxc-exec
  --cwd <dir>          working directory on the VM
  --shell <s>          cmd | powershell | raw (default: the server decides)
  --timeout-ms <n>     default 300000
  --env KEY=VALUE      repeatable
  --path <path>        request path (default /computers/<computer>/<capability>)
  --plaintext          use plain TCP instead of TLS (local RI / loopback DC.Exec)
  -h, --help           show this help
";

struct Args {
    host: String,
    port: u16,
    computer: String,
    token: String,
    capability: String,
    command: String,
    cwd: String,
    shell: Option<String>,
    timeout_ms: u32,
    env: Vec<String>,
    path: Option<String>,
    plaintext: bool,
}

fn next_val(argv: &[String], i: &mut usize, name: &str) -> String {
    *i += 1;
    argv.get(*i).cloned().unwrap_or_else(|| {
        eprintln!("error: {name} requires a value\n\n{USAGE}");
        process::exit(2);
    })
}

fn parse_u16(v: &str, name: &str) -> u16 {
    v.parse().unwrap_or_else(|_| {
        eprintln!("error: {name} must be an integer in 0..=65535\n\n{USAGE}");
        process::exit(2);
    })
}

fn parse_u32(v: &str, name: &str) -> u32 {
    v.parse().unwrap_or_else(|_| {
        eprintln!("error: {name} must be a non-negative integer\n\n{USAGE}");
        process::exit(2);
    })
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let mut host: Option<String> = None;
    let mut port: u16 = 443;
    let mut computer: Option<String> = None;
    let mut token = String::from("unused");
    let mut capability = String::from("microsoft.mxc-exec");
    let mut command: Option<String> = None;
    let mut cwd = String::new();
    let mut shell: Option<String> = None;
    let mut timeout_ms: u32 = 300_000;
    let mut env: Vec<String> = Vec::new();
    let mut path: Option<String> = None;
    let mut plaintext = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].clone();
        match arg.as_str() {
            "--host" => host = Some(next_val(&argv, &mut i, "--host")),
            "--port" => port = parse_u16(&next_val(&argv, &mut i, "--port"), "--port"),
            "--computer" => computer = Some(next_val(&argv, &mut i, "--computer")),
            "--token" => token = next_val(&argv, &mut i, "--token"),
            "--capability" => capability = next_val(&argv, &mut i, "--capability"),
            "--command" => command = Some(next_val(&argv, &mut i, "--command")),
            "--cwd" => cwd = next_val(&argv, &mut i, "--cwd"),
            "--shell" => shell = Some(next_val(&argv, &mut i, "--shell")),
            "--timeout-ms" => {
                timeout_ms = parse_u32(&next_val(&argv, &mut i, "--timeout-ms"), "--timeout-ms")
            }
            "--env" => env.push(next_val(&argv, &mut i, "--env")),
            "--path" => path = Some(next_val(&argv, &mut i, "--path")),
            "--plaintext" => plaintext = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n\n{USAGE}");
                process::exit(2);
            }
        }
        i += 1;
    }

    let require = |v: Option<String>, name: &str| -> String {
        v.unwrap_or_else(|| {
            eprintln!("error: {name} is required\n\n{USAGE}");
            process::exit(2);
        })
    };

    Args {
        host: require(host, "--host"),
        port,
        computer: require(computer, "--computer"),
        token,
        capability,
        command: require(command, "--command"),
        cwd,
        shell,
        timeout_ms,
        env,
        path,
        plaintext,
    }
}

/// Connect (TLS or plaintext), run the §6 relay to completion writing the
/// remote stdout/stderr to `out`/`err`, and return the remote exit code.
fn run(args: &Args, target: UpgradeTarget, start: ExecStartPayload) -> Result<i32, MxcError> {
    let mut out = stdout().lock();
    let mut err = stderr().lock();

    if args.plaintext {
        let mut sock = TcpStream::connect((target.host.as_str(), target.port)).map_err(|e| {
            MxcError::backend_error(format!("connect {}:{}: {e}", target.host, target.port))
        })?;
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|e| MxcError::backend_error(format!("set handshake timeout: {e}")))?;
        sock.write_all(build_upgrade_request(&target)?.as_bytes())
            .and_then(|()| sock.flush())
            .map_err(|e| MxcError::backend_error(format!("send upgrade request: {e}")))?;
        read_upgrade_response(&mut sock)?;
        sock.set_read_timeout(Some(READ_POLL_TIMEOUT))
            .map_err(|e| MxcError::backend_error(format!("set read timeout: {e}")))?;
        run_relay_session(sock, start, &mut out, &mut err, stdin())
    } else {
        let stream = connect_upgrade(&target)?;
        run_relay_session(stream, start, &mut out, &mut err, stdin())
    }
}

fn main() {
    let args = parse_args();

    let path = args
        .path
        .clone()
        .unwrap_or_else(|| format!("/computers/{}/{}", args.computer, args.capability));

    let target = UpgradeTarget {
        host: args.host.clone(),
        port: args.port,
        path,
        computer_id: args.computer.clone(),
        bearer_token: mxc_sdk::w365agents_common::secret::Redacted::new(args.token.clone()),
        capability: args.capability.clone(),
    };

    let start = ExecStartPayload {
        command_line: args.command.clone(),
        working_directory: args.cwd.clone(),
        env: args.env.clone(),
        timeout_ms: args.timeout_ms,
        shell: args.shell.clone(),
    };

    let scheme = if args.plaintext {
        "http (plaintext)"
    } else {
        "https (TLS)"
    };
    eprintln!(
        "[demo] simulated checkout -> host={} computer={} capability={}",
        target.host, target.computer_id, target.capability
    );
    eprintln!(
        "[demo] connecting {scheme}  {}:{}{}",
        target.host, target.port, target.path
    );
    eprintln!("[demo] command: {}", start.command_line);
    eprintln!("[demo] --- remote output ------------------------------");

    match run(&args, target, start) {
        Ok(code) => {
            eprintln!("[demo] --------------------------------------------");
            eprintln!("[demo] remote process exited with code {code}");
            process::exit(code);
        }
        Err(e) => {
            eprintln!("[demo] --------------------------------------------");
            eprintln!("[demo] ERROR: {}", e.message);
            process::exit(1);
        }
    }
}
