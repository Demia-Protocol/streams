// Rust

// 3rd-party
use futures::TryStreamExt;

// IOTA

// Streams
use streams::{
    id::{Ed25519, PermissionDuration, Permissioned, Psk},
    Result, User,
};

// Local
use super::utils::{print_send_result, print_user};
use crate::GenericTransport;

const PUBLIC_PAYLOAD: &[u8] = b"PUBLICPAYLOAD";
const MASKED_PAYLOAD: &[u8] = b"MASKEDPAYLOAD";

const BASE_BRANCH: &str = "BASE_BRANCH";
const BRANCH1: &str = "BRANCH1";
const BRANCH2: &str = "BRANCH2";

pub(crate) async fn example<SR, T: GenericTransport<SR>>(transport: T, author_seed: &str) -> Result<()> {
    let psk = Psk::from_seed("A pre shared key");

    let mut author = User::builder()
        .with_identity(Ed25519::from_seed(author_seed))
        .with_transport(transport.clone())
        .with_psk(psk.to_pskid(), psk)
        .build();

    let mut subscriber_a = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERA9SEED"))
        .with_transport(transport.clone())
        .build();
    let mut subscriber_b = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERB9SEED"))
        .with_transport(transport.clone())
        .build();
    let mut subscriber_c = User::builder()
        .with_psk(psk.to_pskid(), psk)
        .with_transport(transport.clone())
        .build();

    // Confirm that users have id's
    let subscriber_a_id = subscriber_a.identifier().expect("subscriber A should have identifier").clone();
    let subscriber_b_id = subscriber_b.identifier().expect("subscriber B should have identifier").clone();
    assert!(subscriber_c.identifier().is_none());

    println!("> Author creates stream and sends its announcement");
    // Start at index 1, because we can. Will error if its already in use
    let announcement = author.create_stream(BASE_BRANCH).await?;
    print_send_result(&announcement);
    print_user("Author", &author);

    println!("> Subscribers read the announcement to connect to the stream");
    subscriber_a.receive_message(announcement.address()).await?;
    subscriber_b.receive_message(announcement.address()).await?;
    subscriber_c.receive_message(announcement.address()).await?;

    println!("> Subscriber A sends subscription");
    let subscription_a_as_a = subscriber_a.subscribe().await?;
    print_send_result(&subscription_a_as_a);
    print_user("Subscriber A", &subscriber_a);

    println!("> Author reads subscription of subscriber A");
    let subscription_a_as_author = author.receive_message(subscription_a_as_a.address()).await?;
    print_user("Author", &author);

    println!("> Author creates a new branch");
    println!("Branch topic: {}", BRANCH1);
    let branch_announcement = author.new_branch(BASE_BRANCH, BRANCH1).await?;
    print_send_result(&branch_announcement);
    print_user("Author", &author);

    println!("> Author issues keyload for every user subscribed so far [SubscriberA, PSK] in Branch 1");
    let keyload_as_author = author.send_keyload_for_all(BRANCH1).await?;
    print_send_result(&keyload_as_author);
    print_user("Author", &author);

    println!("> Subscribers read branch announcement");
    let branch_1_ann_as_a = subscriber_a
        .messages()
        .try_next()
        .await?
        .expect("Subscriber A did not receive the expected branch announcement");
    assert!(
        branch_1_ann_as_a
            .as_branch_announcement()
            .expect("expected branch announcement, found something else")
            .topic
            .eq(&BRANCH1.into())
    );
    print_user("Subscriber A", &subscriber_a);
    assert_eq!(subscriber_a.sync().await?, 1);

    println!("> Author gives Subscriber A write permission for 5 minutes");
    assert_eq!(author.sync().await?, 1);
    let write_permission_duration = PermissionDuration::seconds_from_now(10); // 5 minutes in seconds
    author
        .send_keyload(
            BRANCH1,
            vec![Permissioned::ReadWrite(subscriber_a_id.clone(), write_permission_duration)],
            vec![],
        )
        .await?;
    assert_eq!(subscriber_a.sync().await?, 1);

    println!("> Subscriber A attempts to send a signed packet (should succeed)");
    let result = subscriber_a
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await;
    assert!(
        result.is_ok(),
        "Subscriber A should be able to send a signed packet before permission expiration"
    );

    // Wait for 6 minutes to ensure the permission is expired
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

    println!("> Subscriber A attempts to send a signed packet (should fail)");
    let result = subscriber_a
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await;

    assert!(
        result.is_err(),
        "Subscriber A should be not able to send a signed packet after permission expiration"
    );
    Ok(())
}