use sqlx::{ mysql::MySqlPoolOptions, MySql, Pool };
use std::error::Error;

pub async fn init_db(connection_string: &str) -> Result<Pool<MySql>, Box<dyn Error>> {
    let pool = MySqlPoolOptions::new().max_connections(5).connect(connection_string).await?;

    sqlx
        ::query(
            r"
        CREATE TABLE IF NOT EXISTS users (
            user_name VARCHAR(255) NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            public_key VARCHAR(500) NOT NULL,
            PRIMARY KEY (user_name)
        )
        "
        )
        .execute(&pool).await?; // @TODO add time created (account/user)

    println!("Database and table initialized successfully");
    Ok(pool)
}

// pub async fn insert_user(
//     pool: &Pool<MySql>,
//     user_name: &str,
//     password_hash: &str,
//     public_key: &str
// ) -> Result<(), sqlx::Error> {
//     sqlx
//         ::query("INSERT INTO users (user_name, password_hash, public_key) VALUES (?, ?, ?)")
//         .bind(user_name)
//         .bind(password_hash)
//         .bind(public_key)
//         .execute(pool).await?;

//     Ok(())
// }

// pub async fn get_user(
//     pool: &Pool<MySql>,
//     user_name: String
// ) -> Result<(String, String), sqlx::Error> {
//     // Switch String String to profile user in the future or smtn
//     let row = sqlx
//         ::query_as::<_, (String, String)>(
//             "SELECT user_name, public_key FROM users WHERE user_name = ?"
//         )
//         .bind(user_name)
//         .fetch_one(pool).await?;

//     Ok(row)
// }

pub async fn user_exists(pool: &Pool<MySql>, user_name: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx
        ::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE user_name = ?")
        .bind(user_name)
        .fetch_one(pool).await?;

    Ok(result > 0)
}
