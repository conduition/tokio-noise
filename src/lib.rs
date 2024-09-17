//! # tokio-noise
//!
//! An authenticated encryption layer on top of [tokio](https://tokio.rs) streams,
//! driven by the [Noise Protocol Framework](https://noiseprotocol.org/).
//!
//! This library is [sponsored by dlcBTC](https://www.dlcbtc.com).
//!
//! ```no_run
//! use tokio::net::{TcpListener, TcpStream};
//! use tokio_noise::{NoiseError, NoiseTcpStream};
//!
//! const PSK: [u8; 32] = [0xFF; 32];
//!
//! async fn run_noise_server(tcp_stream: TcpStream) -> Result<(), NoiseError> {
//!     let mut noise_stream = NoiseTcpStream::handshake_responder_psk0(tcp_stream, &PSK).await?;
//!     let mut buf = [0u8; 1024];
//!     let n = noise_stream.recv(&mut buf).await?;
//!     assert_eq!(&buf[..n], b"hello world");
//!     Ok(())
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), NoiseError> {
//!     let listener = TcpListener::bind("127.0.0.1:0").await?;
//!     let addr = listener.local_addr()?;
//!
//!     let srv = tokio::task::spawn(async move {
//!         let (tcp_stream, _) = listener.accept().await?;
//!         run_noise_server(tcp_stream).await
//!     });
//!
//!     // Client
//!     let tcp_stream = TcpStream::connect(&addr).await?;
//!     let mut noise_stream = NoiseTcpStream::handshake_initiator_psk0(tcp_stream, &PSK).await?;
//!     noise_stream.send(b"hello world").await?;
//!
//!     // Wait for server to finish
//!     srv.await.unwrap()?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

mod errors;
pub mod handshakes;
mod tcp;

pub use errors::*;
pub use tcp::*;

pub use snow;
