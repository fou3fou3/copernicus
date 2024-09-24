mod db;
use askama::Template;
use axum::{
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use copernicus::{
    authenticate_jwt, create_jwt, generate_rsa_keys, hash_password, GetUserTemplate, InputPost,
    InputUser, InsertPost, InsertUser,
};
use db::init_db;
use serde_json::json;
use std::{fs, sync::Arc};

const CONNECTION_STRING: &str = "mysql://admin:admin@localhost:3306/copernicus";
struct AppState {
    pool: sqlx::Pool<sqlx::MySql>,
}

async fn post_api_signin(
    Extension(state): Extension<Arc<AppState>>,
    Json(user): Json<InputUser>,
) -> impl IntoResponse {
    match db::user_exists(&state.pool, &user.user_name).await {
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

    let (private_key, public_key) = match generate_rsa_keys() {
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

async fn post_api_login(
    Extension(state): Extension<Arc<AppState>>,
    Json(user): Json<InputUser>,
) -> impl IntoResponse {
    match db::user_exists(&state.pool, &user.user_name).await {
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

    match db::get_user_password_hash(&state.pool, user.user_name.as_str()).await {
        Ok(password_hash) => {
            if password_hash != hash_password(user.password) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"message": "wrong password unauthorized"})),
                );
            }
        }

        Err(e) => {
            log::error!("failed to retrieve the password hash {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    }

    let token = match create_jwt(user.user_name.clone()) {
        Ok(token) => token,
        Err(e) => {
            log::error!("failed to generate jwt key {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({"message": "ok", "user_name": user.user_name, "jwt_token": token})),
    )
}

async fn get_api_user_profile(
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

    let (user_name, public_key) = match db::get_user(&state.pool, &user_name).await {
        Ok((user_name, public_key)) => (user_name, public_key),
        Err(e) => {
            log::error!("failed to get user {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    };

    let user_posts = match db::get_user_posts(&state.pool, &user_name).await {
        Ok(posts) => posts,
        Err(e) => {
            log::error!("failed to get user posts {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": "internal server error"})),
            );
        }
    };

    (
        StatusCode::OK,
        Json(
            json!({"message": "ok",  "user_name": user_name, "public_key": public_key, "posts": user_posts}),
        ),
    )
}

async fn post_api_post(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(post_data): Json<InputPost>,
) -> impl IntoResponse {
    let auth_header = match headers.get("Authorization") {
        Some(header) => header,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Missing Authorization header"})),
            )
        }
    };

    let auth_header_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Invalid Authorization header"})),
            )
        }
    };

    if let Some(token) = auth_header_str.strip_prefix("Bearer ") {
        let user_name = match authenticate_jwt(token) {
            Ok(user_name) => user_name,

            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"message": "Invalid Authorization header format"})),
                )
            }
        };

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

        match db::insert_post(
            &state.pool,
            InsertPost {
                user_name: user_name.clone(),
                content: post_data.content,
            },
        )
        .await
        {
            Ok(()) => (
                StatusCode::OK,
                Json(json!({"message": "ok", "user_name": user_name})),
            ),
            Err(e) => {
                log::error!("failed to insert post {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"message": "internal server error"})),
                )
            }
        }
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Invalid Authorization header format"})),
        )
    }
}

async fn get_user_profile(Path(user_name): Path<String>) -> Html<String> {
    let get_user_renderer = GetUserTemplate {
        user_name: user_name.as_str(),
    };

    Html(get_user_renderer.render().unwrap())
}

async fn get_signin() -> Html<String> {
    let html_content = fs::read_to_string("templates/signin.html").unwrap();
    return Html(html_content);
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
        .route("/api/login", post(post_api_login))
        .route("/api/user/:user_name", get(get_api_user_profile))
        .route("/api/post", post(post_api_post))
        .route("/user/:user_name", get(get_user_profile))
        .route("/signin", get(get_signin))
        .layer(Extension(shared_data));

    log::info!("initialized app");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    log::info!(target: "serving_events", "serving at 0.0.0.0:3000");

    axum::serve(listener, app).await.unwrap();
}

// @TODO use environment variables to specify certain constants
