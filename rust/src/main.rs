#![allow(unused)]
use bitcoin::hex::DisplayHex;
use bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;

// Node access params
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port
const RPC_USER: &str = "alice";
const RPC_PASS: &str = "password";

// Custom structs for deserializing RPC responses
#[derive(Deserialize, Debug)]
struct CreateWalletResult {
    name: String,
    warning: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ListWalletsResult(Vec<String>);

#[derive(Deserialize, Debug)]
struct GetTransactionResult {
    txid: String,
    fee: Option<f64>,
    details: Vec<TransactionDetail>,
    hex: String,
    decoded: DecodedTransaction,
    blockheight: Option<u64>,
    blockhash: Option<String>,
}

#[derive(Deserialize, Debug)]
struct TransactionDetail {
    address: String,
    category: String,
    amount: f64,
    label: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DecodedTransaction {
    vin: Vec<TransactionInput>,
    vout: Vec<TransactionOutput>,
}

#[derive(Deserialize, Debug)]
struct TransactionInput {
    txid: String,
    vout: u32,
    prevout: Option<PrevOut>,
}

#[derive(Deserialize, Debug)]
struct PrevOut {
    value: f64,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
}

#[derive(Deserialize, Debug)]
struct TransactionOutput {
    value: f64,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
}

#[derive(Deserialize, Debug)]
struct ScriptPubKey {
    address: Option<String>,
}

#[derive(Deserialize, Debug)]
struct MempoolEntry {
    fees: MempoolFees,
}

#[derive(Deserialize, Debug)]
struct MempoolFees {
    base: f64,
}

fn create_or_load_wallet(rpc: &Client, wallet_name: &str) -> bitcoincore_rpc::Result<()> {
    // First check if wallet already exists in the loaded wallets
    let loaded_wallets: ListWalletsResult = rpc.call("listwallets", &[])?;

    if loaded_wallets.0.contains(&wallet_name.to_string()) {
        println!("Wallet '{}' is already loaded", wallet_name);
        return Ok(());
    }

    // Try to create the wallet, if it fails due to existing wallet, try to load it
    let create_result = rpc.call::<CreateWalletResult>("createwallet", &[json!(wallet_name)]);

    match create_result {
        Ok(_) => {
            println!("Created wallet '{}'", wallet_name);
            Ok(())
        }
        Err(_) => {
            // Wallet might already exist, try to load it
            let load_result: Result<Value, _> = rpc.call("loadwallet", &[json!(wallet_name)]);
            match load_result {
                Ok(_) => {
                    println!("Loaded existing wallet '{}'", wallet_name);
                    Ok(())
                }
                Err(e) => {
                    println!("Failed to create or load wallet '{}': {}", wallet_name, e);
                    Err(e)
                }
            }
        }
    }
}

fn get_wallet_client(wallet_name: &str) -> bitcoincore_rpc::Result<Client> {
    let wallet_url = format!("{}/wallet/{}", RPC_URL, wallet_name);
    Client::new(
        &wallet_url,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )
}

fn main() -> bitcoincore_rpc::Result<()> {
    // Connect to Bitcoin Core RPC
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // Get blockchain info
    let blockchain_info = rpc.get_blockchain_info()?;
    println!(
        "Blockchain Info: Chain: {}, Blocks: {}",
        blockchain_info.chain, blockchain_info.blocks
    );

    // Create/Load the wallets, named 'Miner' and 'Trader'
    create_or_load_wallet(&rpc, "Miner")?;
    create_or_load_wallet(&rpc, "Trader")?;

    // Get wallet-specific RPC clients
    let miner_rpc = get_wallet_client("Miner")?;
    let trader_rpc = get_wallet_client("Trader")?;

    // Generate one address from the Miner wallet with label "Mining Reward"
    let mining_address_unchecked = miner_rpc.get_new_address(Some("Mining Reward"), None)?;
    let mining_address = mining_address_unchecked.assume_checked();
    println!("Mining address: {}", mining_address);

    // Mine blocks until we get a positive balance
    // In regtest, coinbase transactions need to mature (100 confirmations) before they can be spent
    let mut blocks_mined = 0;
    let mut balance = Amount::ZERO;

    println!("Mining blocks to generate spendable balance...");
    while balance == Amount::ZERO {
        // Mine 1 block at a time and check balance
        let _block_hashes = rpc.generate_to_address(1, &mining_address)?;
        blocks_mined += 1;
        balance = miner_rpc.get_balance(None, None)?;

        if blocks_mined % 10 == 0 {
            println!(
                "Mined {} blocks, balance: {} BTC",
                blocks_mined,
                balance.to_btc()
            );
        }

        // Safety check to avoid infinite loop
        if blocks_mined > 150 {
            break;
        }
    }

    println!("Mined {} blocks to achieve positive balance", blocks_mined);
    println!("Miner wallet balance: {} BTC", balance.to_btc());

    // Create a receiving address labeled "Received" from Trader wallet
    let trader_address_unchecked = trader_rpc.get_new_address(Some("Received"), None)?;
    let trader_address = trader_address_unchecked.assume_checked();
    println!("Trader receiving address: {}", trader_address);

    // Send 20 BTC from Miner wallet to Trader's wallet
    let send_amount = Amount::from_btc(20.0).unwrap();
    let txid = miner_rpc.send_to_address(
        &trader_address,
        send_amount,
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    println!("Sent transaction ID: {}", txid);

    // Fetch the unconfirmed transaction from the node's mempool
    let mempool_entry: MempoolEntry = rpc.call("getmempoolentry", &[json!(txid.to_string())])?;
    println!(
        "Transaction found in mempool with fee: {} BTC",
        mempool_entry.fees.base
    );

    // Mine 1 block to confirm the transaction
    let _confirm_blocks = rpc.generate_to_address(1, &mining_address)?;
    println!("Mined 1 block to confirm transaction");

    // Get detailed transaction information
    let tx_info: GetTransactionResult = miner_rpc.call(
        "gettransaction",
        &[json!(txid.to_string()), json!(null), json!(true)],
    )?;

    // Extract basic transaction details
    let tx_fee = tx_info.fee.unwrap_or(0.0);
    let block_height = tx_info.blockheight.unwrap();
    let block_hash = tx_info.blockhash.unwrap();

    // Parse the transaction inputs - get the input address and amount
    let vin = &tx_info.decoded.vin[0];
    let miner_input_amount = vin.prevout.as_ref().unwrap().value;
    let miner_input_address = vin
        .prevout
        .as_ref()
        .unwrap()
        .script_pub_key
        .address
        .as_ref()
        .unwrap();

    // Parse outputs to get exact addresses and amounts
    // Find the output that goes to the trader (should be exactly 20 BTC)
    let trader_output = tx_info
        .decoded
        .vout
        .iter()
        .find(|vout| {
            if let Some(addr) = &vout.script_pub_key.address {
                addr == &trader_address.to_string()
            } else {
                false
            }
        })
        .expect("Trader output not found");

    // Find the change output (the other output)
    let miner_change_output = tx_info
        .decoded
        .vout
        .iter()
        .find(|vout| {
            if let Some(addr) = &vout.script_pub_key.address {
                addr != &trader_address.to_string()
            } else {
                false
            }
        })
        .expect("Miner change output not found");

    let miner_change_address = miner_change_output.script_pub_key.address.as_ref().unwrap();

    // Prepare output data
    let trader_output_address = &trader_address.to_string();
    let trader_output_amount = trader_output.value;
    let miner_change_amount = miner_change_output.value;

    // Make sure fee is positive for output
    let fee_amount = if tx_fee < 0.0 { -tx_fee } else { tx_fee };

    // Write the data to out.txt in the specified format
    let mut file = File::create("out.txt")?;
    writeln!(file, "{}", txid)?; // Transaction ID (txid)
    writeln!(file, "{}", miner_input_address)?; // Miner's Input Address
    writeln!(file, "{}", miner_input_amount)?; // Miner's Input Amount (in BTC)
    writeln!(file, "{}", trader_output_address)?; // Trader's Output Address
    writeln!(file, "{}", trader_output_amount)?; // Trader's Output Amount (in BTC)
    writeln!(file, "{}", miner_change_address)?; // Miner's Change Address
    writeln!(file, "{}", miner_change_amount)?; // Miner's Change Amount (in BTC)
    writeln!(file, "{}", fee_amount)?; // Transaction Fees (in BTC)
    writeln!(file, "{}", block_height)?; // Block height at which the transaction is confirmed
    writeln!(file, "{}", block_hash)?; // Block hash at which the transaction is confirmed

    println!("Transaction details written to out.txt");
    println!("Summary:");
    println!("  TXID: {}", txid);
    println!(
        "  Miner Input: {} BTC from {}",
        miner_input_amount, miner_input_address
    );
    println!(
        "  Trader Output: {} BTC to {}",
        trader_output_amount, trader_output_address
    );
    println!(
        "  Miner Change: {} BTC to {}",
        miner_change_amount, miner_change_address
    );
    println!("  Fee: {} BTC", fee_amount);
    println!("  Block Height: {}", block_height);
    println!("  Block Hash: {}", block_hash);

    Ok(())
}
