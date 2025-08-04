use std::{
    ops::Add,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{self, PasswordHasher as _, SaltString, rand_core::OsRng},
};
use rand::{
    Rng,
    distr::{Alphanumeric, SampleString},
};
use rand_chacha::ChaCha12Rng;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};

use crate::data::{AuthToken, Login};

type ID = i64;

const TOKEN_LEN: usize = 2048;

/// Represents a user in the database
#[derive(Debug)]
pub struct User {
    id: ID,
    identity: Box<str>,
    /// Contains both the hash and the salt
    hash: Box<str>,
}

impl User {
    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }
}

/// Represents an authorisation token in the database.
#[derive(Debug)]
pub struct Authorised {
    id: ID,
    token: Box<str>,
    expires: i64,
    user_id: ID,
}

pub async fn connect(options: SqliteConnectOptions) -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePool::connect_with(options).await?;

    sqlx::migrate!().run(&pool).await?;

    Ok(pool)
}

#[derive(thiserror::Error, Debug)]
pub enum GetUserError {
    #[error(transparent)]
    DatabaseError(sqlx::Error),
    /// This is returned if either the identity or password do not match.
    #[error("The requested user does not exist")]
    NonExistent,
}

impl From<sqlx::Error> for GetUserError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::RowNotFound => Self::NonExistent,
            err => Self::DatabaseError(err),
        }
    }
}

pub async fn get_user(pool: &SqlitePool, login: Login) -> Result<User, GetUserError> {
    let username = login.username();

    let user = sqlx::query_as!(
        User,
        r#"
            SELECT * FROM users
            WHERE users.identity == ?
            LIMIT 1
        "#,
        username
    )
    .fetch_one(pool)
    .await?;

    let non_existent = |_| GetUserError::NonExistent;

    let hash = PasswordHash::new(user.hash()).map_err(non_existent)?;

    Argon2::default()
        .verify_password(login.password().as_bytes(), &hash)
        .map_err(non_existent)?;

    Ok(user)
}

#[derive(thiserror::Error, Debug)]
pub enum AddUserError {
    #[error(transparent)]
    DatabaseError(#[from] sqlx::Error),
    #[error(transparent)]
    PasswordHashError(#[from] password_hash::Error),
}

pub async fn add_user(
    pool: &SqlitePool,
    identity: &str,
    password: &str,
) -> Result<(), AddUserError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    sqlx::query!(
        r#"
        INSERT INTO users(identity, hash)
        VALUES(?, ?);
        "#,
        identity,
        hash
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn generate_token(
    pool: &SqlitePool,
    rng: &mut impl Rng,
    user_id: ID,
    expires_in: Duration,
) -> Result<Option<AuthToken>, sqlx::Error> {
    delete_outdated_tokens(pool).await?;

    let user = sqlx::query!("SELECT id FROM users WHERE id = ? LIMIT 1", user_id)
        .fetch_optional(pool)
        .await?;

    let Some(_) = user else { return Ok(None) };

    let token = Alphanumeric.sample_string(rng, TOKEN_LEN);

    // SQLite3 does not support 8 bit unsigned integers.
    let expires: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("UNIX_EPOCH is before current time")
        .add(expires_in)
        .as_secs()
        .try_into()
        .expect("Seconds since UNIX_EPOCH is too large for i64 data type");

    sqlx::query!(
        r#"
        INSERT INTO authorised(token, expires, user_id)
        VALUES(?, ?, ?)
        "#,
        token,
        expires,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(Some(token.into()))
}

/// Checks if the given [`AuthToken`] exists and has not expired.
///
/// Any expired tokens will be removed.
pub async fn valid_token(pool: &SqlitePool, token: AuthToken) -> Result<bool, sqlx::Error> {
    delete_outdated_tokens(pool).await?;

    let record = sqlx::query!(
        r#"
            SELECT * FROM authorised
            WHERE token == ?
            LIMIT 1
        "#,
        token
    )
    .fetch_one(pool)
    .await;

    match record {
        Ok(_) => Ok(true),
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Deletes authorisation tokens that have expired.
async fn delete_outdated_tokens(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // SQLite3 does not support 8 bit unsigned integers.
    let expires: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("UNIX_EPOCH is before current time")
        .as_secs()
        .try_into()
        .expect("Seconds since UNIX_EPOCH is too large for i64 data type");

    sqlx::query!(
        r#"
            DELETE FROM authorised
            WHERE authorised.expires <= ?
        "#,
        expires
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use sqlx::sqlite::SqliteError;
    use std::assert_matches::assert_matches;

    /// The first token generated when using `ChaCha12Rng::from_seed(Default::default())`
    const FIRST_TOKEN: &str = "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";

    #[sqlx::test]
    async fn adding_user(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");
    }

    #[sqlx::test]
    async fn getting_user(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        get_user(&pool, Login::new("test_user", "abced"))
            .await
            .expect("Able to get user");
    }

    #[sqlx::test]
    async fn non_existent_user(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        let get_user = get_user(&pool, Login::new("bad", "abced")).await;
        assert_matches!(get_user, Err(GetUserError::NonExistent));
    }

    #[sqlx::test]
    async fn wrong_password(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        let get_user = get_user(&pool, Login::new("test_user", "wrong")).await;
        assert_matches!(get_user, Err(GetUserError::NonExistent));
    }

    #[sqlx::test]
    async fn generating_token(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        let user = get_user(&pool, Login::new("test_user", "abced"))
            .await
            .expect("Able to get user");

        let mut rng = ChaCha12Rng::from_seed(Default::default());

        generate_token(&pool, &mut rng, user.id(), Duration::default())
            .await
            .expect("Able to generate token");

        let token = sqlx::query!("SELECT token FROM authorised LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("Able to get token")
            .token;

        assert_eq!(token, FIRST_TOKEN);
    }

    #[sqlx::test]
    async fn token_clash(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        let user = get_user(&pool, Login::new("test_user", "abced"))
            .await
            .expect("Able to get user");

        let mut rng = ChaCha12Rng::from_seed(Default::default());

        generate_token(&pool, &mut rng, user.id(), Duration::from_secs(1000))
            .await
            .expect("Able to generate token");

        let mut rng = ChaCha12Rng::from_seed(Default::default());

        let generate_token =
            generate_token(&pool, &mut rng, user.id(), Duration::from_secs(1000)).await;

        // TODO: Prevent this error in the future.
        assert_matches!(generate_token, Err(sqlx::Error::Database(err)) if err.code() == Some(std::borrow::Cow::Borrowed("2067")))
    }

    #[sqlx::test]
    async fn only_outdated_delete(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        let user = get_user(&pool, Login::new("test_user", "abced"))
            .await
            .expect("Able to get user");

        let mut rng = ChaCha12Rng::from_seed(Default::default());

        generate_token(&pool, &mut rng, user.id(), Duration::default())
            .await
            .expect("Able to generate token");

        generate_token(&pool, &mut rng, user.id(), Duration::from_secs(20))
            .await
            .expect("Able to generate token");

        delete_outdated_tokens(&pool)
            .await
            .expect("Able to delete outdated tokens");

        let tokens = sqlx::query!(
            r#"
                SELECT token FROM authorised
            "#
        )
        .fetch_all(&pool)
        .await
        .expect("Able to get authorised")
        .into_iter()
        .map(|token| token.token)
        .collect::<Vec<_>>();

        assert_eq!(
            tokens,
            &[
                "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"
            ]
        )
    }

    #[sqlx::test]
    async fn validate_tokens(pool: SqlitePool) {
        add_user(&pool, "test_user", "abced")
            .await
            .expect("Able to add user to database");

        let user = get_user(&pool, Login::new("test_user", "abced"))
            .await
            .expect("Able to get user");

        let mut rng = ChaCha12Rng::from_seed(Default::default());

        generate_token(&pool, &mut rng, user.id(), Duration::from_secs(1000))
            .await
            .expect("Able to generate token");

        let valid_token = valid_token(&pool, FIRST_TOKEN.into())
            .await
            .expect("Able to validate token");

        assert!(valid_token);
    }
}
