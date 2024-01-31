<h1 align="center">
  <br>
  <a href="https://wiki.iota.org/streams/welcome"><img src="streams.png"></a>
</h1>

<h3 align="center">!!! Attention: This is a continuation of the IOTA Streams library for use in the Digital MRV ecosystem, and is not fully compatible with existing stardust implementations with IOTA nodes</h2>
<h2 align="center">A cryptographic framework for building secure messaging protocols</h2>

<p align="center">

<a href="https://wiki.iota.org/streams/welcome" style="text-decoration:none;">
    <img src="https://img.shields.io/badge/Documentation%20portal-blue.svg?style=for-the-badge"
         alt="Developer documentation portal">
      </p>
<p align="center">
    <a href="https://raw.githubusercontent.com/iotaledger/streams/master/LICENSE" style="text-decoration:none;"><img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="Apache 2.0 license"></a>
</p>

<p align="center">
  <a href="#about">About</a> ◈
  <a href="#prerequisites">Prerequisites</a> ◈
  <a href="#installation">Installation</a> ◈
  <a href="#getting-started">Getting started</a> ◈
  <a href="#api-reference">API reference</a> ◈
  <a href="#examples">Examples</a> ◈
  <a href="#supporting-the-project">Supporting the project</a> 
</p>

---

## About

Streams is a **work-in-progress** framework for building cryptographic messaging protocols. Streams ships with a built-in protocol for sending authenticated messages between two or more parties on a DAG network (like the IOTA Tangle).

At the moment, IOTA Streams includes the following crates:
* [Application Logic](streams/README.md) featuring User and high level messaging logic.
* [Spongos](spongos/README.md) featuring data definition and manipulation language for protocol messages;
* [LETS](lets/README.md) featuring the building blocks for application logic, including low level messaging logic.
* [C Bindings](bindings/c/README.md).

## Prerequisites
To use IOTA Streams, you need the following:
- [Rust](https://www.rust-lang.org/tools/install)
- (Optional) An IDE that supports Rust autocompletion. We recommend [Visual Studio Code](https://code.visualstudio.com/Download) with the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=matklad.rust-analyzer) extension

We also recommend updating Rust to the [latest stable version](https://github.com/rust-lang/rustup.rs#keeping-rust-up-to-date):

```bash
rustup update stable
```


## Installation

To use the library in your crate you need to add it as a dependency in the `Cargo.toml` file.

Because the library is not on [crates.io](https://crates.io/), you need to use the Git repository either remotely or locally.

`no_std` is currently supported for standard seed based Users, but not if the `did` feature is enabled.
Cargo nightly must be used to build with `no_std` feature.

## Getting started

If you don't have a rust project setup yet you can create one by running,

    cargo new my-library

**Remote**
Add the following to your `Cargo.toml` file:

```bash
[dependencies]
anyhow = { version = "1.0", default-features = false }
iota-streams = { git = "https://github.com/demia-protocol/streams", branch  = "develop"}
```

**Local**

1. Clone this repository

    ```bash
    git clone https://github.com/iotaledger/streams
    ```

2. Add the following to your `Cargo.toml` file:

    ```bash
    [dependencies]
    iota-streams = { version = "0.2.1", path = "../streams" }
    ```

## Getting started

After you've [installed the library](#installation), you can use it in your own Cargo project.

For example, you may want to use the application protocol to create a new user like so:
```
use streams::{
    transport::utangle,
    id::Ed25519,
    User
};

#[tokio::main] 
async fn main() {
   let node = "http://localhost:14265";
   let transport = utangle::Client::new(node);
   let mut author = User::builder()
     .with_identity(Ed25519::from_seed("A cryptographically secure seed"))
     .with_transport(transport)
     .build();

   // A new stream, or branch within a stream will require a Topic label
   let topic = "BASE_BRANCH"
   let announcement = author.create_stream(topic).await?;
}
```

For a more detailed guide, go to the legacy IOTA [documentation portal](https://wiki.iota.org/streams/welcome).
Currently, this guide is parity with the current functionality. A future portal is in the works.

## API reference

To generate the API reference and display it in a web browser, do the following:

```bash
cargo doc --open
```

## Examples

We have several examples in the [`examples` directory](streams/examples/full-example/scenarios), which you can use as a reference when developing your own protocols with IOTA Streams.

You can run the examples yourself on a local bucket test instance by running:
```
cargo run --example full-example --features="bucket" 
```

If you would like to run them using an existing node, you can do so by copying the [`example.env`](streams/examples/full-example/example.env) file
and updating the `URL` variable to the appropriate node url, and changing the `TRANSPORT` variable to `utangle`. Run the above command in
`--release` mode.

## Supporting the project

Please see our [contribution guidelines](CONTRIBUTING.md) for all the ways in which you can contribute.

### Running tests

We use code comments to write tests. You can run all tests by doing the following from the `streams` directory:

```
cargo test --all
```

### Updating documentation

If you want to improve the code comments, please do so according to the guidelines in [RFC 1574](https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#appendix-a-full-conventions-text).
