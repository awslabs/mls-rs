#![cfg(not(target_arch = "wasm32"))]
use test_utils::passive_client_test_generation::{
    generate_passive_client_proposal_tests, generate_passive_client_welcome_tests,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures::future::join(
        generate_passive_client_proposal_tests(),
        generate_passive_client_welcome_tests(),
    )
    .await;

    Ok(())
}