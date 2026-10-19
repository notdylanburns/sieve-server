use super::{PgConnection, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: Box<str>,
}

#[derive(sqlx::FromRow)]
pub struct Credentials {
    pub id: i64,
    pub username: Box<str>,
    pub password_hash: Box<str>,
}

impl Credentials {
    pub fn user(&self) -> User {
        User {
            id: self.id,
            username: self.username.clone(),
        }
    }
}

pub async fn create(conn: &mut PgConnection, username: &str, password_hash: &str) -> Result<User> {
    sqlx::query_as(
        "
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        RETURNING id, username
        ",
    )
    .bind(username)
    .bind(password_hash)
    .fetch_one(conn)
    .await
}

/// Returns None when no user has that username.
pub async fn set_password_hash(
    conn: &mut PgConnection,
    username: &str,
    password_hash: &str,
) -> Result<Option<User>> {
    sqlx::query_as(
        "
        UPDATE users
        SET password_hash = $2
        WHERE username = $1
        RETURNING id, username
        ",
    )
    .bind(username)
    .bind(password_hash)
    .fetch_optional(conn)
    .await
}

pub async fn get(conn: &mut PgConnection, id: i64) -> Result<Option<User>> {
    sqlx::query_as("SELECT id, username FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(conn)
        .await
}

pub async fn find_by_username(conn: &mut PgConnection, username: &str) -> Result<Option<User>> {
    sqlx::query_as("SELECT id, username FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(conn)
        .await
}

/// Returns None for users without a password, such as those who sign in with Google.
pub async fn find_credentials(
    conn: &mut PgConnection,
    username: &str,
) -> Result<Option<Credentials>> {
    sqlx::query_as(
        "
        SELECT id, username, password_hash
        FROM users
        WHERE username = $1 AND password_hash IS NOT NULL
        ",
    )
    .bind(username)
    .fetch_optional(conn)
    .await
}

pub async fn find_by_google_sub(conn: &mut PgConnection, sub: &str) -> Result<Option<User>> {
    sqlx::query_as("SELECT id, username FROM users WHERE google_sub = $1")
        .bind(sub)
        .fetch_optional(conn)
        .await
}

/// Creates a passwordless user named after their email. If a user already has that name, the
/// Google subject id is appended to keep it unique.
pub async fn create_google(conn: &mut PgConnection, email: &str, sub: &str) -> Result<User> {
    sqlx::query_as(
        "
        INSERT INTO users (username, google_sub)
        SELECT
            CASE WHEN EXISTS (SELECT 1 FROM users WHERE username = $1)
                THEN $1 || '#' || $2
                ELSE $1
            END,
            $2
        RETURNING id, username
        ",
    )
    .bind(email)
    .bind(sub)
    .fetch_one(conn)
    .await
}
