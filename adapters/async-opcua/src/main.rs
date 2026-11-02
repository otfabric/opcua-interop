//! opcua-interop adapter for async-opcua (https://github.com/FreeOpcUa/async-opcua).
//!
//! Subcommands: `server`, `client <op>`, `print-capabilities`,
//! `validate-fixture`, `test`. See docs/CONTAINER_CONTRACT.md.

mod caps;
mod client;
mod codec;
mod common;
mod discovery;
mod fixture;
mod nodeid;
mod pki;
mod selftest;
mod server;
mod values;

use std::io::Write;

fn init_logging(args: &[String]) {
    // Without an application certificate (SecurityPolicy None) the stack logs
    // errors about the missing certificate on every channel; silence those.
    // Routine client notices (no configured endpoints: the adapter selects
    // them itself; "Transport disconnected: Good" on a clean close) are noise.
    let base = "warn,opcua_client::config=error,opcua_client::session::event_loop=error";
    let default = if args.iter().any(|a| a == "--certificate") {
        base.to_owned()
    } else {
        format!(
            "{base},opcua_crypto::certificate_store=off,opcua_client::session::client=off,\
             opcua_core::comms::secure_channel=off,opcua_server::server=error"
        )
    };
    let env = env_logger::Env::default().default_filter_or(default);
    env_logger::Builder::from_env(env)
        .target(env_logger::Target::Stderr)
        .format(|buf, rec| writeln!(buf, "[async-opcua] {}: {}: {}", rec.level(), rec.target(), rec.args()))
        .init();
}

fn usage() {
    eprintln!(
        "usage: opcua-interop-async-opcua <server|client|validate-fixture|print-capabilities|test> [args...]"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        usage();
        std::process::exit(1);
    };
    let rest = args[1..].to_vec();
    if cmd == "print-capabilities" {
        std::process::exit(caps::run());
    }
    if cmd == "validate-fixture" {
        std::process::exit(fixture::validate_command(&rest));
    }
    if cmd == "test" {
        std::process::exit(selftest::run(&rest));
    }
    init_logging(&rest);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = match cmd.as_str() {
        "server" => rt.block_on(server::run(&rest)),
        "client" => rt.block_on(client::run(&rest)),
        _ => {
            eprintln!("unknown subcommand: {cmd}");
            usage();
            1
        }
    };
    rt.shutdown_timeout(std::time::Duration::from_millis(500));
    std::process::exit(code);
}
