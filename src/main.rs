#[macro_use]
extern crate rocket;
mod db;

use db::init_db;

const CONNECTION_STRING: &str = "mysql://admin:admin@localhost:3306/copernicus";

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

// #[get("/api/signin")]
// fn api_signin() -> &'static str {
//     "Hello, world!"
// }

#[launch]
async fn rocket() -> _ {
    let _ = init_db(CONNECTION_STRING).await.unwrap();

    rocket::build().mount("/", routes![index])
}
