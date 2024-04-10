// Rust
use std::env;

// 3rd-party
#[cfg(not(feature = "did"))]
use rand::Rng;

// IOTA

// Streams
#[cfg(all(not(feature = "did"), feature = "bucket"))]
use streams::transport::bucket;
use streams::{transport::Transport, Result, TransportMessage};

#[cfg(feature = "tangle-client")]
use streams::transport::tangle;

#[cfg(feature = "utangle-client")]
use streams::transport::utangle;

mod scenarios;

// #[derive(Deserialize)]
// struct Ignored {}

// cargo run --example full-example
trait GenericTransport<SR>:
    for<'a> Transport<'a, Msg = TransportMessage, SendResponse = SR> + Clone + Send + Sync
{
}

impl<T, SR> GenericTransport<SR> for T where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = SR> + Clone + Send + Sync
{
}

#[cfg(feature = "did")]
async fn run_did_scenario<SR, T: GenericTransport<SR>>(transport: T) -> Result<()> {
    println!("## Running DID Test ##\n");
    let result = scenarios::did::example(transport).await;
    match &result {
        Err(err) => eprintln!("Error in DID test: {:?}", err),
        Ok(_) => println!("\n## DID test completed successfully!! ##\n"),
    }
    result
}

#[cfg(not(feature = "did"))]
async fn run_lean_test<SR, T: GenericTransport<SR>>(transport: T, seed: &str) -> Result<()> {
    println!("## Running Lean State Test ##\n");
    let result = scenarios::lean::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in Lean State test: {}", err),
        Ok(_) => println!("\n## Lean State test completed successfully!! ##\n"),
    }
    result
}

#[cfg(not(feature = "did"))]
async fn run_basic_scenario<SR, T: GenericTransport<SR>>(transport: T, seed: &str) -> Result<()> {
    println!("## Running single branch test with seed: {} ##\n", seed);
    let result = scenarios::basic::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in Single Branch test: {}", err),
        Ok(_) => println!("\n## Single Branch Test completed successfully!! ##\n"),
    };
    result
}

#[cfg(not(feature = "did"))]
async fn run_filter_branch_test<SR, T: GenericTransport<SR>>(
    transport: T,
    seed: &str,
) -> Result<()> {
    println!("## Running filter test with seed: {} ##\n", seed);
    let result = scenarios::filter::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in filter test: {}", err),
        Ok(_) => println!("\n## Filter Test completed successfully!! ##\n"),
    };
    result
}

#[cfg(not(feature = "did"))]
async fn main_pure() -> Result<()> {
    println!("\n");
    println!("###########################################");
    println!("Running pure tests without accessing Tangle");
    println!("###########################################");
    println!("\n");

    let transport = bucket::Client::new();

    run_basic_scenario(transport.clone(), "PURESEEDA").await?;
    run_lean_test(transport.clone(), "PURESEEDB").await?;
    run_filter_branch_test(transport.clone(), "PURESEEDC").await?;
    println!("################################################");
    println!("Done running pure tests without accessing Tangle");
    println!("################################################");
    Ok(())
}

async fn run_expiration<SR, T: GenericTransport<SR>>(transport: T, seed: &str) -> Result<()> {
    println!("## Running expiration test with seed: {} ##\n", seed);
    let result = scenarios::expired::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in expiration test: {}", err),
        Ok(_) => println!("\n## Expiration Test completed successfully!! ##\n"),
    };
    result
}

#[cfg(feature = "tangle-client")]
async fn main_tangle_client() -> Result<()> {
    // Parse env vars with a fallback
    let node_url =
        env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    println!("\n");
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!(
        "Running tests accessing Tangle with iota.rs via node {}",
        &node_url
    );
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!("\n");

    let transport: tangle::Client = tangle::Client::for_node(&node_url)
        .await
        .unwrap_or_else(|e| panic!("error connecting Tangle client to '{}': {}", node_url, e));

    #[cfg(feature = "did")]
    run_did_scenario(transport.clone()).await?;
    #[cfg(not(feature = "did"))]
    {
        run_basic_scenario(transport.clone(), &new_seed()).await?;
        run_lean_test(transport.clone(), &new_seed()).await?;
        run_filter_branch_test(transport.clone(), &new_seed()).await?;
    }

    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!(
        "Done running tests accessing Tangle with iota.rs via node {}",
        &node_url
    );
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    Ok(())
}

#[cfg(feature = "utangle-client")]
async fn main_utangle_client() -> Result<()> {
    // Parse env vars with a fallback
    let node_url =
        env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    println!("\n");
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!(
        "Running tests accessing Tangle with uTangle via node {}",
        &node_url
    );
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!("\n");

    let transport: utangle::Client = utangle::Client::new(&node_url);

    run_expiration(transport, &new_seed()).await?;
    #[cfg(feature = "did")]
    //run_did_scenario(transport.clone()).await?;
    #[cfg(not(feature = "did"))]
    {
        run_basic_scenario(transport.clone(), &new_seed()).await?;
        run_lean_test(transport, &new_seed()).await?;
    }

    println!(
        "##########################################################{}",
        "#".repeat(node_url.len())
    );
    println!(
        "Done running tests accessing Tangle with uTangle via node {}",
        &node_url
    );
    println!(
        "##########################################################{}",
        "#".repeat(node_url.len())
    );
    Ok(())
}

#[cfg(not(feature = "did"))]
fn new_seed() -> String {
    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    (0..10)
        .map(|_| {
            alph9
                .chars()
                .nth(rand::thread_rng().gen_range(0..27))
                .unwrap()
        })
        .collect::<String>()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load or .env file, log message if we failed
    if dotenv::dotenv().is_err() {
        println!(".env file not found; copy and rename example.env to \".env\"");
    };

    match env::var("TRANSPORT").ok().as_deref() {
        #[cfg(feature = "utangle-client")]
        Some("utangle") => main_utangle_client().await,
        #[cfg(feature = "tangle-client")]
        Some("tangle") => main_tangle_client().await,
        #[cfg(not(feature = "did"))]
        // Pure test only works when DID is not a feature
        Some("bucket") => main_pure().await,
        Some(other) => panic!("Unexpected TRANSPORT '{}'", other),
        None => panic!("No transport"),
    }
}
