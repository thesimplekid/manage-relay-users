use axum::http::HeaderMap;
use error::Error;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

use nauthz_grpc::authorization_server::{Authorization, AuthorizationServer};
use nauthz_grpc::{Decision, EventReply, EventRequest};

use crate::config::Settings;
use crate::repo::Repo;

use serde::Deserialize;

use axum::{
    extract::{Json, State},
    routing::post,
    Router,
};

use std::sync::Arc;

use tokio::task;
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
    pub repo: Arc<Mutex<Repo>>,
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
                self.repo
                    .lock()
                    .await
                    .handle_admission_update(event)
                    .await
                    .unwrap();

                // TODO: This is testing comment out
                self.repo.lock().await.get_all_accounts().unwrap();
            }

            return Ok(Response::new(nauthz_grpc::EventReply {
                decision: Decision::Permit as i32,
                message: Some("Ok".to_string()),
            }));
        }

        // Check user is in DB
        if let Ok(Some(user_account)) = self.repo.lock().await.get_account(&author) {
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

    let repo = Arc::new(Mutex::new(Repo::new()));

    repo.lock().await.get_all_accounts()?;

    let checker = EventAuthz {
        repo: repo.clone(),
        settings: settings.clone(),
    };

    // run this in a new thread
    let handle = task::spawn(start_server(settings.info.api_key.clone(), repo));

    info!("EventAuthz Server listening on {addr}");
    // Start serving
    Server::builder()
        .add_service(AuthorizationServer::new(checker))
        .serve(addr)
        .await?;

    handle.await.unwrap()?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    api_key: String,
    repo: Arc<Mutex<Repo>>,
}

async fn start_server(api_key: String, repo: Arc<Mutex<Repo>>) -> Result<(), Error> {
    let shared_state = AppState {
        api_key: api_key.to_string(),
        repo,
    };

    // build our application with a single route
    let app = Router::new()
        .route("/update", post(update_users))
        .with_state(shared_state);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Users {
    allow: Vec<String>,
    deny: Vec<String>,
}

async fn update_users(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<Users>,
) {
    if let Some(key) = headers.get("X-Api-Key") {
        if key.eq(&state.api_key) {
            // Admit pubkeys
            state
                .repo
                .lock()
                .await
                .admit_pubkeys(&payload.allow)
                .await
                .ok();

            // Deny pubkeys
            state
                .repo
                .lock()
                .await
                .deny_pubkeys(&payload.deny)
                .await
                .ok();
        }
    }
}
