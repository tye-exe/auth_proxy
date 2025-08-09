use serde::{Deserialize, Serialize};

/// The authorisation token the client can use to authorise future requests without having to login again.
#[derive(Deserialize, Serialize, Debug, sqlx::Type)]
#[sqlx(transparent)]
pub struct AuthToken(Box<str>);

impl AuthToken {
    pub fn token(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for AuthToken {
    fn from(value: T) -> Self {
        Self(Into::<String>::into(value).into_boxed_str())
    }
}

/// The login details sent by the client.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Login {
    username: Box<str>,
    password: Box<str>,
}

impl Login {
    pub fn new(username: impl Into<Box<str>>, password: impl Into<Box<str>>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Information about users in the proxy process.
#[derive(Deserialize, Serialize, Debug)]
pub struct UserState {
    /// The url data originally requested.
    path: Box<str>,
    stage: Stage,
}

impl UserState {
    pub fn new(path: Box<str>) -> Self {
        Self {
            path,
            stage: Stage::default(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn set_stage(mut self, stage: Stage) -> Self {
        self.stage = stage;
        self
    }
}

/// The state of the user in the proxy process.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub enum Stage {
    /// User is at login screen.
    #[default]
    Login,
    /// User has been authenticated.
    Authenticated,
    /// User resquested to reset their password.
    PasswordReset,
    /// User changed their password.
    PasswordChanged,
}
