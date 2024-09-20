use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::error::Error;

pub async fn init_db(connection_string: &str) -> Result<Pool<MySql>, Box<dyn Error>> {
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(connection_string)
        .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS users (
            user_name VARCHAR(255) NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            public_key VARCHAR(500) NOT NULL,
            PRIMARY KEY (user_name)
        )
        ",
    )
    .execute(&pool)
    .await?;

    println!("Database and table initialized successfully");
    Ok(pool)
}
