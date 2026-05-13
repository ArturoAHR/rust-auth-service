use std::{error::Error, sync::Arc};

use axum::{
    http::{status::StatusCode, Method},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};

use redis::{Client, RedisResult};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::{net::TcpListener, sync::RwLock};
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use domain::AuthApiError;
use tracing::info;

use crate::{
    domain::{BannedTokenStore, EmailClient, TwoFactorAuthCodeStore, UserStore},
    utils::tracing::{make_span_with_request_id, on_request, on_response},
};

pub type AppStateUserStore = Arc<RwLock<dyn UserStore>>;
pub type AppStateBannedTokenStore = Arc<RwLock<dyn BannedTokenStore>>;
pub type AppStateTwoFactorAuthCodeStore = Arc<RwLock<dyn TwoFactorAuthCodeStore>>;
pub type AppStateEmailClient = Arc<dyn EmailClient>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: AppStateUserStore,
    pub banned_token_store: AppStateBannedTokenStore,
    pub two_factor_auth_code_store: AppStateTwoFactorAuthCodeStore,
    pub email_client: AppStateEmailClient,
}

impl AppState {
    pub fn new(
        user_store: AppStateUserStore,
        banned_token_store: AppStateBannedTokenStore,
        two_factor_auth_code_store: AppStateTwoFactorAuthCodeStore,
        email_client: AppStateEmailClient,
    ) -> Self {
        Self {
            user_store,
            banned_token_store,
            two_factor_auth_code_store,
            email_client,
        }
    }
}

pub struct Application {
    server: Serve<TcpListener, Router, Router>,

    pub address: String,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        log_error_chain(&self);

        let (status, error_message) = match self {
            AuthApiError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthApiError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthApiError::UnexpectedError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthApiError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthApiError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthApiError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };

        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        (status, body).into_response()
    }
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir = ServeDir::new("assets");

        let allowed_origins = ["http://localhost:8000".parse()?];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(routes::sign_up))
            .route("/login", post(routes::login))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/logout", post(routes::logout))
            .route("/verify-token", post(routes::verify_token))
            .with_state(app_state)
            .layer(cors)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(make_span_with_request_id)
                    .on_request(on_request)
                    .on_response(on_response),
            );

        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        info!("Listening on {}", &self.address);
        self.server.await
    }
}

pub async fn get_postgres_pool(url: &SecretString) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(url.expose_secret())
        .await
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);

    redis::Client::open(redis_url)
}

fn log_error_chain(e: &(dyn Error + 'static)) {
    let separator =
        "\n-----------------------------------------------------------------------------------\n";
    let mut report = format!("{}{:?}\n", separator, e);
    let mut current = e.source();

    while let Some(cause) = current {
        let str = format!("Caused by:\n\n{:?}", cause);

        report = format!("{}\n{}", report, str);
        current = cause.source();
    }

    report = format!("{}\n{}", report, separator);
    eprintln!("{}", report);
}
