use tokio::net::{TcpListener, TcpStream};
use tokio_noise::{
    handshakes::{nn_psk2, NNpsk2},
    NoiseError, NoiseTcpStream,
};

const PSK: [u8; 32] = [0xFF; 32];

async fn run_noise_server(tcp_stream: TcpStream) -> Result<(), NoiseError> {
    let mut responder = nn_psk2::Responder::new(|id: &[u8]| -> Option<&[u8]> {
        if id != b"client_id_123".as_ref() {
            return None;
        }
        Some(&PSK)
    });

    let mut noise_stream =
        NoiseTcpStream::handshake_responder(tcp_stream, NNpsk2::new(&mut responder)).await?;

    assert_eq!(
        responder.initiator_identity(),
        Some(b"client_id_123".as_ref())
    );

    let mut buf = [0u8; 1024];
    let n = noise_stream.recv(&mut buf).await?;
    assert_eq!(&buf[..n], b"hello world");
    Ok(())
}

#[tokio::test]
async fn main() -> Result<(), NoiseError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let srv = tokio::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await?;
        run_noise_server(tcp_stream).await
    });

    // Client
    let initiator = nn_psk2::Initiator {
        psk: &PSK,
        identity: b"client_id_123",
    };
    let tcp_stream = TcpStream::connect(&addr).await?;
    let mut noise_stream =
        NoiseTcpStream::handshake_initiator(tcp_stream, NNpsk2::new(initiator)).await?;
    noise_stream.send(b"hello world").await?;

    // Wait for server to finish
    srv.await.unwrap()?;

    Ok(())
}
