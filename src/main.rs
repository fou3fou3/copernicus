mod db;
use axum::{extract::Extension, routing::get, Json, Router};
use copernicus::AuthUser;
use db::init_db;
use serde_json::{json, Value};
use std::sync::Arc;

const CONNECTION_STRING: &str = "mysql://admin:admin@localhost:3306/copernicus";
struct AppState {
    pool: sqlx::Pool<sqlx::MySql>,
}

async fn post_api_signin(
    Extension(state): Extension<Arc<AppState>>,
    Json(user): Json<AuthUser>,
) -> Json<Value> {
    match db::user_exists(&state.pool, user.user_name.as_str()).await {
        Ok(user_exists) => {
            if user_exists {
                return Json(json!({"message": "user name already used", "code": 406}));
            }
        }
        Err(e) => {
            println!("{}", e);
            return Json(json!({"message": "internal server error", "code": 500}));
        }
    }

    Json(json!({"message": "ok", "code": 200, "user_name": user.user_name}))
}

#[tokio::main]
async fn main() {
    let pool = init_db(CONNECTION_STRING).await.unwrap();

    let shared_data = Arc::new(AppState { pool });

    let app = Router::new()
        .route("/api/signin", get(post_api_signin))
        .layer(Extension(shared_data));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
