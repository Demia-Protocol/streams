# Streams Application layer: core definitions and User logic.
This library serves as a continuation of the [IOTA Streams](http://github.com/iotaledger/streams) library. Updated 
features and development will be catered towards `Demia` functionality and other data focused distributed networks. 

Legacy documentation [here](https://wiki.iota.org) (an updated docs is in works to replace the old linkage with the Iota 
wiki, these old docs are reflective of the v1.x versions of Streams. Although many core concepts remain the same, much 
of the API has changed, one would be better served to build the docs locally for the current API)

### Docs
Build Docs locally with `cargo doc --manifest-path streams/Cargo.toml --open` which will pull up the v2.x Streams API 
documentation. You can add the `--document-private-items` flag if you would like to take a deeper dive.


## Streams Application 
The streams application layer is a High-level Implementation of the Streams Protocol. Streams users will generate a 
[`User`](src/api/user.rs) instance to publish and retrieve messages within a network (preferably a distributed data network). The default
usage of this library is over an [IOTA Tangle](https://wiki.iota.org/learn/about-iota/an-introduction-to-iota/) style 
network. Existing Transport Client implementations can be found in the [LETS](../lets/README.md) crate, and custom 
Clients can be created so long as they implement the [`Transport`](../lets/src/transport/mod.rs) trait).

------------

## Getting Started
Import the library into your crate
```
streams = { git = "https://github.com/demia-protocol/streams", default-features = false, features = ["did", "utangle-client"] }
```

------------
#### Create a Stream and Send Messages 
The first step in a stream is to define a User instance to create the stream with. This will require 3 things: 
1) A transport `Client` for a compatible network
2) An `Identity` instance representing the User (the built-in default is seed based `Ed25519` identification) 
3) A `Topic` label that will be used for the base branch of the stream

Once a user is created, they can attempt to create a new stream using the provided `Topic` label. A stream announcement 
address cannot be the same as an existing message, but provided the `Identity` and `Topic` are unique, there should not 
be a collision. Once the stream is created, you can start sending messages, and creating access control models using 
branching and `Keyload` messages.

```rust
 use streams::{
    transport::utangle,
    id::Ed25519,
    User, Result
 };
 
#[tokio::main]
async fn main() -> Result<()> { 
    // Create a transport Client for the desired network
    let transport: utangle::Client = utangle::Client::new("https://chrysalis-nodes.iota.org");
    
    // Define an Identity type for the author (eg. Ed25519 from seed, DIDInfo from existing DID user)
    let identity = Ed25519::from_seed("A cryptographically secure seed");
    // Create a user
    let mut author = User::builder()
        .with_identity(identity)
        .with_transport(transport)
        .build();

    // Define a base topic for your stream
    let topic = "Stream Topic";
    
    // Announce the Stream, the address can then be provided to the intended publishers and subscribers
    // so they can find the message and attach
    let announcement = author.create_stream(topic).await?;
    
    // In a public channel, no permissions are set and any messages sent can be read by anyone who has processed the 
    // `Announce` message. 
    
    for i in 1..11 {
        // Send message to the branch, the response of which will contain the address should you wish it, although 
        // aside from the `Announce` message, all other readable messages are discovered via the subscribing users 
        // instances, so there is no need to share any more than the original announcement message 
        let message = author.message()
            .with_topic(topic)
            .with_payload(format!("Message #{i}"))
            .signed()
            .send()
            .await?;
    }
    
    Ok(())
}
```

#### Including a User
There are 2 ways to include a new user into a Stream: 
1) Added via `Subscribe` message address
```rust
let subscription_msg = author.receive_message(subscription_address).await?;
```
2) Manually entered via command 
```rust
author.add_subscriber(subscriber_identifier);
```
#### Create a New Branch, and Grant Write Permission
You can create a new branch from any existing branch, and then modify the permissions of that sub branch to grant users
read and write permissions, creating a tree like structure of access permissions. It is important to note that a user 
will need to have permission to a previous branch in order to see the new branch announcement message.
```rust
// Create a new branch topic
let new_branch_topic = "A new branch topic";

// Assign permissions for the branch
let subscriber_permissions = vec![Permissioned::ReadWrite(sub_identifier, PermissionDuration::Perpetual]

// List any pre-shared keys for identityless read permissions
let psks = vec![psk_id1, psk_id2];

// Announce the creation of a new branch inside the old branch
let branch_announcement = author.new_branch(old_branch_topic, new_branch_topic).await?;

// Create a new keyload containing the lists of permissions to the new branch
let new_branch_permissions = author.send_keyload(new_branch_topic, )

// Send a private message into the new branch 
author.message()
    .with_topic(new_branch_topic)
    .with_payload("Hello predefined subscribers")
    .signed()
    .send()
    .await?;

// Subscriber now has permission to write to this branch, so first it should retrieve any missing messages 
let messages = sub.messages();
while let Some(msg) = messages.try_next().await {
    // The user should have been able to see the branch announcement and processed the subsequent keyload message, this
    // will allow them to keep reading and see the signed packet
    if let MessageContent::SignedPacket(id, masked, public) = msg {
        // Once the packet is found you can extract the contents
        assert_eq!(masked, b"Hello predefined subscribers");
    } 
}

// Now they can start writing as well 
sub.message()
    .with_topic(new_branch_topic)
    .with_payload("Hello fellow subscribers")
    .signed()
    .send()
    .await?;
```

------------

#### Subscribe to Stream and Fetch Messages
Once a stream has been created, publishers and subscribers can begin to interact with the author in order to establish
participation credentials. 

The most basic kind of subscriber is to a public stream. They do not need to communicate with
the author of the stream aside from to retrieve the announcement message link. They can then begin reading messages as 
they appear. These Users do not need to use an Identity if they do not wish to, as they are not publishing or trying to 
read encrypted messages. 
```rust 
// Create a transport Client for the desired network
let transport: utangle::Client = utangle::Client::new("https://chrysalis-nodes.iota.org");
        
// Create the subscribing user
let mut subscriber = User::builder()
    .with_transport(transport)
    .build();
        
// Subscriber fetches announcement message and attaches to the instance
subscriber.receive_message(announcement_address).await?;
    
// Subscriber begins a message retrieval stream and begins fetching
let messages = subscriber.messages();
loop {
    // Check for a next message
    messages.try_next()
        .await
        .map(|msg| {
            // Once a message is found, you can match the contents with a type 
            match msg.content() {
                // Signed message with an associated `Identifier` 
                MessageContent::SignedPacket(id, masked, public) => ...,
                // Unsigned message, verified by HMAC but not by Id
                MessageContent::TaggedPacket(masked, public) => ...,
                // Not a message with a payload so we'll ignore it
                _ => 
            }
                
            // Or you can try to cast to a specific message type 
            if let Some(signed_packet) = msg.as_signed_packet() {
                ...
            }
        })
}
```

A more complex access control model requires communication between the new users and the author of the stream. That can 
be done by providing your User `Identifier` to the author oob, or by sending a `Subscribe` message and providing the 
author with the `Address` of that message. 
```rust
// Create a User with a defined identity
let identity = Ed25519::from_seed("Unique seed for subscriber");
let mut subscriber = User::builder()
    .with_transport(transport)
    .with_identity(identity)
    .build();
// You can provide this identity to the author, or...
assert_eq!(subscriber.identifier(), Some(identity.public().into()));

// You can send a `Subscribe` message and provide the subscription message address to the author instead 
let subscription = subscriber.subscribe().await?;
```
 
-----------

For more [examples](examples/full-example/main.rs) on general usage such as Subscription, DID usage, branch creation, permission management, 
message retrieval etc.

### Features
`default`: The default features include the uTangle client and std 
`std`: Run without this for low level `no-std` compatible functionality
`did`: Enables [DID](https://github.com/iotaledger/identity.rs) identifier logic
`utangle-client`: Enable re-export of uTangle transport client from LETS
`tangle-client`: Enable re-export of IOTA-Tangle transport client from LETS
`bucket`: Re-export of testing Hashset style Bucket transport client from LETS
`tangle-client-wasm`: Enable re-export of wasm-compatible IOTA-Tangle transport client from LETS (incompatile with `tangle-client` feature due to `iota-client/async` using `tokio`)
`mysql-client`: Enable re-export of MySql transport client from LETS


## More Info

### [Spongos](../spongos/README.md)
The Spongos crate houses core functionality for `DDML` (Data Description Markup Language) and sponge based cryptographic
operations. The core module houses trait bounds for `Pseudo-Random Permutation` instances (the default implementation 
used in this library is `Keccak-f[1600]`), as well as the custom `Spongos` wrapper, which makes up the foundation of 
state management and `DDML` command operations. The ddml module houses `Spongos` based commands for 
encoding/decoding/encryption/signature functionality.

### [LETS](../lets/README.md)
The `LETS` crate houses message-oriented cryptographic protocols. Identification, transportation and generic message 
handling protocols in these modules can be used to build streaming applications. Signature and encryption operations are 
handled via the `id` module, while `message` encoding operations are managed via the `message` module. Messages are 
indexed by an `Address` composed of an `Application Address` and `Message Identifier`, and the library provides a 
`Transport` trait to allow for agnostic transport client creation.


## Customization
If you are looking to extend the implementations to customise your application experience, we welcome you to explore 
the generation of new [`message types`](src/message/mod.rs), [`Identities`](../lets/src/id/identity.rs) and 
[`Cryptographic`](../spongos/src/lib.rs) functionality. Making new messages requires that you use 
[`DDML syntax`](../spongos/src/ddml/mod.rs) and implement the [`Content Wrap/Unwrap traits`](../lets/src/message/content.rs).
`DDML` can be extended to accommodate any deficiencies present for your implementations.

If your custom implementations appear to have more universal applicability, we openly welcome feature pull requests.
