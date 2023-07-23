use axum::http::HeaderMap;
use clap::Parser;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

use nauthz_grpc::authorization_server::{Authorization, AuthorizationServer};
use nauthz_grpc::{Decision, EventReply, EventRequest};

use crate::cli::CLIArgs;
use crate::config::Settings;
use crate::repo::Repo;

use serde::{Deserialize, Serialize};

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};

use std::sync::Arc;

use tokio::task;
use tracing::{debug, info};

pub mod nauthz_grpc {
    tonic::include_proto!("nauthz");
}

pub mod cli;
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
    let args = CLIArgs::parse();

    let settings = config::Settings::new(&args.config);

    let db_path = match args.db {
        Some(path) => Some(path),
        None => settings.info.db_path.clone(),
    };

    let repo = Arc::new(Mutex::new(Repo::new(db_path)));

    repo.lock().await.get_all_accounts()?;

    let checker = EventAuthz {
        repo: repo.clone(),
        settings: settings.clone(),
    };

    // run this in a new thread
    if let Some(api_key) = settings.info.api_key {
        let port = settings.info.api_listen_port.unwrap_or(3000);
        let host = settings
            .info
            .api_listen_host
            .unwrap_or("127.0.0.1".to_string());
        let _handle = task::spawn(async move {
            if let Err(err) = start_server(api_key, &host.clone(), port, repo).await {
                log::warn!("{}", err);
            }
        });
    }

    info!("EventAuthz Server listening on {addr}");
    // Start serving
    Server::builder()
        .add_service(AuthorizationServer::new(checker))
        .serve(addr)
        .await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    api_key: String,
    repo: Arc<Mutex<Repo>>,
}

async fn start_server(
    api_key: String,
    host: &str,
    port: u16,
    repo: Arc<Mutex<Repo>>,
) -> anyhow::Result<()> {
    let shared_state = AppState {
        api_key: api_key.to_string(),
        repo,
    };

    // build our application with a single route
    let app = Router::new()
        .route("/update", post(update_users))
        .route("/users", get(get_users))
        .with_state(shared_state);

    let server_add = format!("{}:{}", host, port).parse()?;

    // run it with hyper on localhost:3000
    axum::Server::bind(&server_add)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Users {
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
}

async fn update_users(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<Users>,
) -> Result<(), (StatusCode, String)> {
    debug!("Users: {payload:?}");
    if let Some(key) = headers.get("X-Api-Key") {
        debug!("Sent key: {key:?}");
        if key.eq(&state.api_key) {
            // Admit pubkeys
            if let Some(pubkeys) = &payload.allow {
                debug!("Pubkeys to allow: {pubkeys:?}");
                state.repo.lock().await.admit_pubkeys(&pubkeys).await.ok();
            }

            // Deny pubkeys
            if let Some(pubkeys) = &payload.deny {
                debug!("Pubkeys to deny: {pubkeys:?}");
                state.repo.lock().await.deny_pubkeys(&pubkeys).await.ok();
            }
            return Ok(());
        }
    }

    Err((StatusCode::UNAUTHORIZED, "".to_string()))
}

async fn get_users(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Users>, (StatusCode, String)> {
    debug!("{}", state.api_key);
    if let Some(key) = headers.get("X-Api-Key") {
        if key.eq(&state.api_key) {
            let users = state.repo.lock().await.get_accounts().unwrap();
            return Ok(Json(users));
        }
        return Err((StatusCode::UNAUTHORIZED, "Invalid API Key".to_string()));
    }

    Err((StatusCode::UNAUTHORIZED, "No Api Key".to_string()))
}
