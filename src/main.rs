mod db;

use db::init_db;

// const DB_NAME: &str = "copernicus";
const CONNECTION_STRING: &str = "mysql://admin:admin@localhost:3306/copernicus";

#[tokio::main]
async fn main() {
    let _ = init_db(CONNECTION_STRING).await.unwrap();
}
