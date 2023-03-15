use tonic::{transport::Server, Request, Response, Status};

use nauthz_grpc::authorization_server::{Authorization, AuthorizationServer};
use nauthz_grpc::{Decision, EventReply, EventRequest};

use crate::config::Settings;
use crate::repo::Repo;

use tracing::{debug, info};

pub mod nauthz_grpc {
    tonic::include_proto!("nauthz");
}

pub mod config;
pub mod db;
pub mod error;
pub mod repo;
pub mod utils;

pub struct EventAuthz {
    pub repo: Repo,
    pub settings: Settings,
}

#[tonic::async_trait]
impl Authorization for EventAuthz {
    async fn event_admit(
        &self,
        request: Request<EventRequest>,
    ) -> Result<Response<EventReply>, Status> {
        let req = request.into_inner();
        let event = req.clone().event.unwrap();
        let content_prefix: String = event.content.chars().take(40).collect();
        info!("recvd event, [kind={}, origin={:?}, nip05_domain={:?}, tag_count={}, content_sample={:?}]",
                 event.kind, req.origin, req.nip05.as_ref().map(|x| x.domain.clone()), event.tags.len(), content_prefix);

        let author = match req.auth_pubkey {
            Some(_) => req.auth_pubkey(),
            None => &event.pubkey,
        };

        let author = hex::encode(author);

        // If author is trusted pubkey decode event and update account(s)
        // admit event
        if self.settings.info.admin_keys.contains(&author) {
            // I just picked this kind number should maybe put more thought into it, NIP?
            if event.kind == 4242 {
                // TODO: Spawn this to not block
                self.repo.handle_admission_update(event).await.unwrap();

                // TODO: This is testing comment out
                self.repo.get_all_accounts().unwrap();
            }

            return Ok(Response::new(nauthz_grpc::EventReply {
                decision: Decision::Permit as i32,
                message: Some("Ok".to_string()),
            }));
        }

        // Check user is in DB
        if let Ok(Some(user_account)) = self.repo.get_account(&author) {
            // Check user admission status
            if user_account.is_admitted() {
                return Ok(Response::new(nauthz_grpc::EventReply {
                    decision: Decision::Permit as i32,
                    message: Some("Ok".to_string()),
                }));
            }
        }

        Ok(Response::new(nauthz_grpc::EventReply {
            decision: Decision::Deny as i32,
            message: Some("Not allowed to publish".to_string()),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();

    tracing_subscriber::fmt::try_init().unwrap();

    let settings = config::Settings::new(&None);

    debug!("{:?}", settings);

    let repo = Repo::new();

    repo.get_all_accounts()?;

    let checker = EventAuthz { repo, settings };

    info!("EventAuthz Server listening on {addr}");
    // Start serving
    Server::builder()
        .add_service(AuthorizationServer::new(checker))
        .serve(addr)
        .await?;
    Ok(())
}
