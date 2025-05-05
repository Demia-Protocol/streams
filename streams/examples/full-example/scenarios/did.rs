// Rust

use std::sync::Arc;
// 3rd-arty
use anyhow::anyhow;
use textwrap::{fill, indent};

// IOTA
use identity_demia::{
    demia::{
        block::{address::Address, output::AliasOutputBuilder},
        DemiaDocument, IotaClientExt, IotaIdentityClientExt, NetworkName,
    },
    did::DID as IdentityDID,
    verification::{MethodData, MethodScope, MethodType, VerificationMethod},
};

use iota_sdk::{
    client::{
        api::GetAddressesOptions, node_api::indexer::query_parameters::QueryParameter,
        secret::SecretManager, Client as DIDClient,
    },
    crypto::keys::bip39,
    types::block::{address::ToBech32Ext, output::Output},
};

use iota_stronghold::types::Location;

// Streams
use streams::{
    id::{
        did::{DIDInfo, DIDUrlInfo, StrongholdSecretManager, DID, STREAMS_VAULT},
        Ed25519, Permissioned, Psk,
    },
    Result, User,
};

use super::utils::{print_send_result, print_user};
use crate::GenericTransport;

const PUBLIC_PAYLOAD: &[u8] = b"PUBLICPAYLOAD";
const MASKED_PAYLOAD: &[u8] = b"MASKEDPAYLOAD";
const CLIENT_URL: &str = "http://localhost:14280";

const STRONGHOLD_PASSWORD: &str = "temp_stronghold_password";
const STRONGHOLD_URL: &str = "temp_stronghold";
const FAUCET: &str = "http://localhost:8091/api/enqueue";
const BASE_BRANCH: &str = "BASE_BRANCH";
const BRANCH1: &str = "BRANCH1";

const DEFALT_COUNTRY: isocountry::CountryCode = isocountry::CountryCode::USA;

pub(crate) async fn example<SR, T: GenericTransport<SR>>(transport: T) -> Result<()> {
    let did_client = DIDClient::builder()
        .with_local_pow(true)
        .with_primary_node(CLIENT_URL, None)
        .map_err(|e| anyhow!(e.to_string()))?
        .finish()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    println!("> Making DID with method for the Author");
    let author_did_info = make_did_info(
        &did_client,
        "#auth_key",
        "#auth_xkey",
        "#auth_signing_key",
        "auth",
    )
    .await?;
    println!("> Making another DID with methods for one of the Subscribers");
    let subscriber_a_did_info = make_did_info(
        &did_client,
        "#sub_a_key",
        "#sub_a_xkey",
        "#subA_signing_key",
        "subA",
    )
    .await?;
    //let subscriber_b_did_info =
    //    make_did_info(&did_client, "sub_b_key", "sub_b_xkey", "subB_signing_key", "subB").await?;

    // Generate a simple PSK for storage by users
    let psk = Psk::from_seed("A pre shared key");

    let mut author = User::builder()
        .with_identity(DID::PrivateKey(author_did_info))
        .with_transport(transport.clone())
        .with_psk(psk.to_pskid(), psk)
        .build();
    let mut subscriber_a = User::builder()
        .with_identity(DID::PrivateKey(subscriber_a_did_info))
        .with_transport(transport.clone())
        .build();
    let mut subscriber_b = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBER B UNIQUE SEED"))
        .with_transport(transport.clone())
        .build();
    let mut subscriber_c = User::builder()
        .with_psk(psk.to_pskid(), psk)
        .with_transport(transport.clone())
        .build();

    println!("> Author creates stream and sends its announcement");
    // Start at index 1, because we can. Will error if its already in use
    let announcement = author.create_stream(BASE_BRANCH).await?;
    print_send_result(&announcement);
    print_user("Author", &author);

    println!("> Subscribers read the announcement to connect to the stream");
    subscriber_a.receive_message(announcement.address()).await?;
    print_user("Subscriber A", &subscriber_a);
    subscriber_b.receive_message(announcement.address()).await?;
    print_user("Subscriber B", &subscriber_b);
    subscriber_c.receive_message(announcement.address()).await?;
    print_user("Subscriber C", &subscriber_c);

    // Predefine Subscriber A
    println!("> Subscribers A and B sends subscription");
    let subscription_a_as_a = subscriber_a.subscribe().await?;
    print_send_result(&subscription_a_as_a);
    print_user("Subscriber A", &subscriber_a);

    let subscription_b_as_b = subscriber_b.subscribe().await?;
    print_send_result(&subscription_b_as_b);
    print_user("Subscriber A", &subscriber_b);

    println!("> Author reads subscription of subscribers A and B");
    let _subscription_a_as_author = author
        .receive_message(subscription_a_as_a.address())
        .await?;
    let subscription_b_as_author = author
        .receive_message(subscription_b_as_b.address())
        .await?;
    print_user("Author", &author);

    println!("> Author creates new branch");
    let branch_announcement = author.new_branch(BASE_BRANCH, BRANCH1).await?;
    print_send_result(&branch_announcement);
    print_user("Author", &author);

    println!("> Author issues keyload for everybody [Subscriber A, Subscriber B, PSK]");
    let first_keyload_as_author = author.send_keyload_for_all(BRANCH1).await?;
    print_send_result(&first_keyload_as_author);
    print_user("Author", &author);

    println!("> Author sends 3 signed packets linked to the keyload");
    for _ in 0..3 {
        let last_msg = author
            .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
            .await?;
        print_send_result(&last_msg);
    }
    print_user("Author", &author);

    println!("> Author issues new keyload for only Subscriber B and PSK");
    let second_keyload_as_author = author
        .send_keyload(
            BRANCH1,
            [Permissioned::Read(
                subscription_b_as_author.header().publisher().clone(),
            )],
            [psk.to_pskid()],
        )
        .await?;
    print_send_result(&second_keyload_as_author);
    print_user("Author", &author);

    println!("> Author sends 2 more signed packets linked to the latest keyload");
    for _ in 0..2 {
        let last_msg = author
            .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
            .await?;
        print_send_result(&last_msg);
    }
    print_user("Author", &author);

    println!("> Author sends 1 more signed packet linked to the first keyload");
    let last_msg = author
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    print_send_result(&last_msg);
    print_user("Author", &author);

    println!("> Subscriber C receives 9 messages:");
    let messages_as_c = subscriber_c.fetch_next_messages().await?;
    print_user("Subscriber C", &subscriber_c);
    for message in &messages_as_c {
        println!("\t{}", message.address());
        println!(
            "{}",
            indent(&fill(&format!("{:?}", message.content()), 140), "\t| ")
        );
        println!("\t---");
    }
    assert_eq!(9, messages_as_c.len());

    println!("> Subscriber B receives 9 messages:");
    let messages_as_b = subscriber_b.fetch_next_messages().await?;
    print_user("Subscriber B", &subscriber_b);
    for message in &messages_as_b {
        println!("\t{}", message.address());
        println!(
            "{}",
            indent(&fill(&format!("{:?}", message.content()), 140), "\t| ")
        );
        println!("\t---");
    }
    assert_eq!(9, messages_as_b.len());

    println!("> Subscriber A receives 7 messages:");
    let messages_as_a = subscriber_a.fetch_next_messages().await?;
    print_user("Subscriber A", &subscriber_a);
    for message in &messages_as_a {
        println!("\t{}", message.address());
        println!(
            "{}",
            indent(&fill(&format!("{:?}", message.content()), 140), "\t| ")
        );
        println!("\t---");
    }
    assert_eq!(6, messages_as_a.len());

    Ok(())
}

async fn make_did_info(
    did_client: &DIDClient,
    doc_signing_fragment: &str,
    exchange_fragment: &str,
    signing_fragment: &str,
    stronghold_ext: &str,
) -> anyhow::Result<DIDInfo> {
    // Make stronghold adapter
    let adapter = stronghold_adapter(stronghold_ext)?;

    // Create a signing key for Identity and store the mnemonic key
    let secret: SecretKey = SecretKey::generate().unwrap();
    let public: PublicKey = secret.public_key();

    let mnemonic = bip39::wordlist::encode(secret.as_slice(), &bip39::wordlist::ENGLISH)
        .map_err(|err| anyhow!(format!("{err:?}")))?;
    adapter
        .store_mnemonic(mnemonic)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    let mut stronghold = SecretManager::Stronghold(adapter);
    let address = request_faucet_funds(did_client, &mut stronghold).await?;

    // Retrieve Outputs
    let b32_address = address.to_bech32(did_client.get_bech32_hrp().await?);
    println!("Bech32 address {}", b32_address);
    let output_ids = did_client
        .basic_output_ids(vec![QueryParameter::Address(b32_address)])
        .await?;
    let outputs = did_client.get_outputs(&output_ids.items).await?;
    let mut total_amount = 0;
    // Check available balance
    for output_response in outputs {
        if let Output::Basic(output) = output_response.output() {
            total_amount += output.amount();
        }
    }
    assert!(total_amount > 0, "not enough balance for identity");

    // Create the root document, publish it and test resolving it
    let doc = new_doc(
        did_client,
        &mut stronghold,
        &public,
        doc_signing_fragment,
        address,
    )
    .await?;

    let mut doc = did_client
        .resolve_did(doc.id())
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    // Generate a signing and exchange keypair to be used by the streams instance, storing them in the
    // stronghold
    generate_streams_keys(
        &mut stronghold,
        &mut doc,
        &secret,
        doc_signing_fragment,
        signing_fragment,
        exchange_fragment,
    )
    .await?;

    // Resolve the latest output and update it with the given document, updating the storage deposit for
    // the new rent structure
    let alias_output = did_client.update_did_output(doc.clone()).await?;
    let rent_structure = did_client.get_rent_structure().await?;
    let alias_output = AliasOutputBuilder::from(&alias_output)
        .with_minimum_storage_deposit(rent_structure)
        .finish()?;

    // Publish the updated Alias Output.
    let updated = did_client
        .publish_did_output(&stronghold, alias_output, &DEFALT_COUNTRY)
        .await?;

    // Create a new DIDInfo object with the stronghold included
    match stronghold {
        SecretManager::Stronghold(stronghold) => {
            let mut url_info = DIDUrlInfo::new(
                updated.id().clone(),
                CLIENT_URL,
                exchange_fragment,
                signing_fragment,
            );
            url_info = url_info.with_stronghold(Arc::new(RwLock::new(stronghold)));
            Ok(DIDInfo::new(url_info))
        }
        _ => Err(anyhow!("unexpected Stronghold type")),
    }
}

// Fetch the stronghold adapter for the provided user
fn stronghold_adapter(ext: &str) -> Result<StrongholdSecretManager> {
    Ok(StrongholdSecretManager::builder()
        .password(STRONGHOLD_PASSWORD.to_owned())
        .build(STRONGHOLD_URL.to_owned() + "_" + ext)
        .map_err(|e| anyhow!(e.to_string()))?)
}

// Request the funds for the Identity to be stored with
async fn request_faucet_funds(
    did_client: &DIDClient,
    stronghold: &mut SecretManager,
) -> anyhow::Result<Address> {
    // Fetch addresseses from the stronghold adapter for faucet funds
    let addresses = stronghold
        .generate_ed25519_addresses(
            GetAddressesOptions::from_client(did_client)
                .await?
                .with_range(0..1),
        )
        .await?;
    let b32_address = addresses[0];
    println!("Requesting funds for {}", b32_address);
    iota_sdk::client::request_funds_from_faucet(FAUCET, &b32_address).await?;

    println!("Waiting 10 seconds for deposit to enact");
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    Ok(addresses[0].into_inner())
}

// Create a new IOTA DID document and publish it
async fn new_doc(
    did_client: &DIDClient,
    stronghold: &mut SecretManager,
    doc_public: &PublicKey,
    doc_signing_fragment: &str,
    output_address: Address,
) -> anyhow::Result<DemiaDocument> {
    // Create a new document with a base method
    let network_name: NetworkName = did_client.get_network_name().await?.try_into()?;
    let mut doc = DemiaDocument::new(&DEFALT_COUNTRY, &network_name);

    // let jwk: Jwk = encode_public_ed25519_jwk(&doc_public);
    // let _method = VerificationMethod::new_from_jwk(doc.id().clone(), jwk, Some(&doc_signing_fragment)).map_err(|e| anyhow!(e.to_string()))?;

    let method = VerificationMethod::builder(Default::default())
        .id(doc.id().to_url().join(doc_signing_fragment)?)
        .controller(doc.id().to_url().did().clone())
        .type_(MethodType::ED25519_VERIFICATION_KEY_2018)
        .data(MethodData::PublicKeyMultibase(
            BaseEncoding::encode_multibase(doc_public.as_slice(), None),
        ))
        .build()?;

    doc.insert_method(method, MethodScope::VerificationMethod)?;

    // Create new alias output and publish it
    let output = did_client.new_did_output(output_address, doc, None).await?;
    Ok(did_client
        .publish_did_output(&stronghold, output, &DEFALT_COUNTRY)
        .await?)
}

// Create the Ed25519 and X25519 keys that will be used by the streams user and store them into the
// stronghold vaults
async fn generate_streams_keys(
    stronghold: &mut SecretManager,
    doc: &mut DemiaDocument,
    doc_secret: &SecretKey,
    doc_signing_fragment: &str,
    signing_fragment: &str,
    exchange_fragment: &str,
) -> anyhow::Result<()> {
    let method = doc
        .resolve_method(&format!("#{doc_signing_fragment}"), None)
        .expect("Should be able to fetch method from newly made doc");

    let doc_key_location = Location::generic(STREAMS_VAULT, method.id().to_string());

    match stronghold {
        SecretManager::Stronghold(adapter) => {
            // Store keys in vault
            let vault = adapter.vault_client(STREAMS_VAULT).await?;
            vault.write_secret(doc_key_location, doc_secret.as_slice().to_vec().into())?;

            // insert new methods
            let signing_private = SecretKey::generate()?;
            let exchange_private = crypto::keys::x25519::SecretKey::generate()?;

            let signing_method = VerificationMethod::builder(Default::default())
                .id(doc.id().to_url().join(signing_fragment)?)
                .controller(doc.id().to_url().did().clone())
                .type_(MethodType::ED25519_VERIFICATION_KEY_2018)
                .data(MethodData::PublicKeyMultibase(
                    BaseEncoding::encode_multibase(&signing_private.public_key(), None),
                ))
                .build()?;

            let exchange_method = VerificationMethod::builder(Default::default())
                .id(doc.id().to_url().join(exchange_fragment)?)
                .controller(doc.id().to_url().did().clone())
                .type_(MethodType::X25519_KEY_AGREEMENT_KEY_2019)
                .data(MethodData::PublicKeyMultibase(
                    BaseEncoding::encode_multibase(&exchange_private.public_key(), None),
                ))
                .build()?;

            let signing_key_location =
                Location::generic(STREAMS_VAULT, signing_method.id().to_string());
            let exchange_key_location =
                Location::generic(STREAMS_VAULT, exchange_method.id().to_string());

            // Store new methods in vault
            vault.write_secret(
                signing_key_location,
                signing_private.as_slice().to_vec().into(),
            )?;
            vault.write_secret(
                exchange_key_location,
                exchange_private.to_bytes().to_vec().into(),
            )?;

            // Insert methods into document
            doc.insert_method(signing_method, MethodScope::VerificationMethod)?;
            doc.insert_method(exchange_method, MethodScope::VerificationMethod)?;
            Ok(())
        }
        _ => return Err(anyhow!("unexpected Stronghold type").into()),
    }
}

use crypto::signatures::ed25519::PublicKey;
use crypto::signatures::ed25519::SecretKey;
use identity_demia::core::BaseEncoding;
use identity_demia::core::Object;
use identity_demia::did::CoreDID;
use identity_demia::document::CoreDocument;
use identity_demia::verification::jwk::EdCurve;
use identity_demia::verification::jwk::Jwk;
use identity_demia::verification::jwk::JwkParamsOkp;
use identity_demia::verification::jws::JwsAlgorithm;
use identity_demia::verification::jwu;
use tokio::sync::RwLock;

pub(crate) fn encode_public_ed25519_jwk(public_key: &PublicKey) -> Jwk {
    let x = jwu::encode_b64(public_key.as_ref());
    let mut params = JwkParamsOkp::new();
    params.x = x;
    params.d = None;
    params.crv = EdCurve::Ed25519.name().to_string();
    let mut jwk = Jwk::from_params(params);
    jwk.set_alg(JwsAlgorithm::EdDSA.name());
    jwk
}

pub(crate) fn generate_jwk_document_with_keys() -> (CoreDocument, SecretKey, String) {
    let secret: SecretKey = SecretKey::generate().unwrap();
    let public: PublicKey = secret.public_key();
    let jwk: Jwk = encode_public_ed25519_jwk(&public);

    let did: CoreDID = CoreDID::parse(format!(
        "did:example:{}",
        BaseEncoding::encode_base58(&public)
    ))
    .unwrap();
    let fragment: String = "#jwk".to_owned();
    let document: CoreDocument = CoreDocument::builder(Object::new())
        .id(did.clone())
        .verification_method(VerificationMethod::new_from_jwk(did, jwk, Some(&fragment)).unwrap())
        .build()
        .unwrap();
    (document, secret, fragment)
}
