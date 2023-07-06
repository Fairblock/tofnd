//! [proto::gg20_server::Gg20] gRPC server API
//! Available gRPCs are:
//!     [recover] - Recovers private data of a party provided a mnemonic.
//!     [keygen] - Starts keygen.
//!     [sign] - Starts sing.

// tonic cruft
use super::proto;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status};
pub mod proto_helpers;

// logging
use tracing::{error, info, span, Level};

// gRPC
mod broadcast;
mod key_presence;
mod keygen;
mod protocol;
mod recover;
pub mod service;
//mod sign;
pub mod types;
use types::*;

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for service::Gg20Service {
    type KeygenStream = UnboundedReceiverStream<Result<proto::MessageOut, tonic::Status>>;

    // /// KeyPresence unary gRPC. See [key_presence].
    async fn key_presence(
        &self,
        request: tonic::Request<proto::KeyPresenceRequest>,
    ) -> Result<Response<proto::KeyPresenceResponse>, Status> {
        let request = request.into_inner();

        let response = match self.handle_key_presence(request).await {
            Ok(res) => {
                info!("Key presence check completed succesfully!");
                res
            }
            Err(err) => {
                error!("Unable to complete key presence check: {}", err);
                proto::key_presence_response::Response::Fail
            }
        };

        Ok(Response::new(proto::KeyPresenceResponse {
            response: response as i32,
        }))
    }

    /// Keygen streaming gRPC. See [keygen].
    async fn keygen(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        info!("Key gen called succesfully!");

        let stream_in = request.into_inner();
        let (msg_sender, rx) = mpsc::unbounded_channel();

        // log span for keygen
        let span = span!(Level::INFO, "Keygen");
        let _enter = span.enter();
        let s = span.clone();
        let gg20 = self.clone();

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = gg20.handle_keygen(stream_in, msg_sender.clone(), s).await {
                error!("keygen failure: {:?}", e.to_string());
                // we can't handle errors in tokio threads. Log error if we are unable to send the status code to client.
                if let Err(e) = msg_sender.send(Err(Status::invalid_argument(e.to_string()))) {
                    error!("could not send error to client: {}", e.to_string());
                }
            }
        });

        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}
