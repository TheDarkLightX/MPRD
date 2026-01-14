//! Tau Testnet node smoke test for MPRD integration wiring.
//!
//! This test is intentionally small:
//! - spawn Tau Testnet node in `TAU_FORCE_TEST=1` mode (no Docker required)
//! - issue a couple of commands over TCP
//!
//! If this fails, MPRD cannot currently use Tau Testnet as an integration harness.

use mprd_core::tau_testnet::{
    default_tau_testnet_dir_from_manifest, pick_free_local_port, TauTestnetClient, TauTestnetNode,
    TauTestnetNodeOptions,
};

#[test]
fn tau_testnet_node_boots_and_answers_commands() {
    let port = pick_free_local_port().expect("free port");
    let tau_dir = default_tau_testnet_dir_from_manifest();

    let opts = TauTestnetNodeOptions::dev_default(tau_dir, port);
    let node = TauTestnetNode::spawn(opts).expect(
        "failed to start tau-testnet node. If you see ModuleNotFoundError for trio/trio_websocket, run tools/tau-testnet/setup_venv.sh and set TAU_TESTNET_PYTHON to the venv python.",
    );

    let client = TauTestnetClient::new(node.addr());

    // Basic liveness.
    let ts = client.call("gettimestamp").expect("gettimestamp");
    assert!(
        !ts.is_empty() && !ts.to_lowercase().contains("error"),
        "unexpected gettimestamp response: {ts}"
    );

    // Wallet-oriented commands used by web-wallet.
    let accounts = client.call("getallaccounts").expect("getallaccounts");
    assert!(
        !accounts.is_empty(),
        "unexpected getallaccounts response (empty)"
    );
}

