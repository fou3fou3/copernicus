mod db;
use askama::Template;
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use copernicus::{hash_password, AuthUser, GetUserTemplate, InsertUser};
use db::init_db;
use serde_json::json;
use std::sync::Arc;

const CONNECTION_STRING: &str = "mysql://admin:admin@localhost:3306/copernicus";
struct AppState {
    pool: sqlx::Pool<sqlx::MySql>,
}

async fn post_api_signin(
    Extension(state): Extension<Arc<AppState>>,
    Json(user): Json<AuthUser>,
) -> impl IntoResponse {
    match db::user_exists(&state.pool, user.user_name.as_str()).await {
        Ok(user_exists) => {
            if user_exists {
                return (
                    StatusCode::NOT_ACCEPTABLE,
                    Json(json!({"message": "user name already used"})),
                );
            }
        }
        Err(e) => {
            log::error!("failed to check if user exists {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    }

    let (private_key, public_key) = match copernicus::generate_rsa_keys() {
        Ok((private_key, public_key)) => (private_key, public_key),
        Err(e) => {
            log::error!("failed to generate rsa keys {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    };

    let user_to_be_inserted = InsertUser {
        user_name: user.user_name.clone(),
        password_hash: hash_password(user.password),
        public_key,
    };

    match db::insert_user(&state.pool, user_to_be_inserted).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"message": "ok", "user_name": user.user_name, "private_key": private_key})),
        ),
        Err(e) => {
            log::error!("failed to insert user {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            )
        }
    }
}

async fn get_api_user(
    Extension(state): Extension<Arc<AppState>>,
    Path(user_name): Path<String>,
) -> impl IntoResponse {
    match db::user_exists(&state.pool, &user_name).await {
        Ok(user_exists) => {
            if !user_exists {
                return (
                    StatusCode::NOT_ACCEPTABLE,
                    Json(json!({"message": "user does not exist"})),
                );
            }
        }
        Err(e) => {
            log::error!("failed to check if user exists {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    }

    match db::get_user(&state.pool, user_name).await {
        Ok((user_name, public_key)) => (
            StatusCode::OK,
            Json(json!({"message": "ok",  "user_name": user_name, "public_key": public_key})),
        ),
        Err(e) => {
            log::error!("failed to get user {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            )
        }
    }
}

async fn get_user(Path(user_name): Path<String>) -> Html<String> {
    let get_user_renderer = GetUserTemplate {
        user_name: user_name.as_str(),
    };

    Html(get_user_renderer.render().unwrap()) // This wont panic unless there are not the necessary templates which are essential .
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let pool = init_db(CONNECTION_STRING).await.unwrap();
    log::info!(target: "db_events", "sucessfully initialized db");

    let shared_data = Arc::new(AppState { pool });

    let app = Router::new()
        .route("/api/signin", post(post_api_signin))
        .route("/api/user/:user_name", get(get_api_user))
        .route("/user/:user_name", get(get_user))
        .layer(Extension(shared_data));

    log::info!("initialized app");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    log::info!(target: "serving_events", "serving at 0.0.0.0:3000");

    axum::serve(listener, app).await.unwrap();
}
