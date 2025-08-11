mod async_read;

use crate::{
    cli::async_read::{from_tty, from_tty_hidden},
    database,
};
use log::{error, trace, warn};
use sqlx::SqlitePool;
use zeroize::Zeroizing;

const HELP_TEXT: &str = r#"
Help:
- To add a new user enter 'user add'.
  You will be prompted for an identity and password.
"#;

/// Handles the user input from the terminal.
pub async fn handle_user_input(pool: SqlitePool) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = input(&pool).await {
                warn!("Terminal not available, you will be unable to add users.");
                warn!("If you are using docker add the '-it' flags.");
                trace!("Error: {err}");
                return;
            }
        }
    });
}

/// Process input
async fn input(pool: &sqlx::Pool<sqlx::Sqlite>) -> Result<(), std::io::Error> {
    let input = from_tty().await?;

    match input
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["user", "add"] => {
            eprint!("Identity: ");
            let identity = from_tty().await?;

            let password = get_password().await?;

            match database::add_user(pool, &identity, &password).await {
                Ok(_) => {
                    eprintln!("User added successfully")
                }
                Err(err) => {
                    error!("Unable to add user: {err}")
                }
            };
        }
        ["help"] | _ => {
            eprintln!("{}", HELP_TEXT)
        }
    }

    Ok(())
}

/// Prompts the user to enter a password.
/// This method will not return until a password is repeated correctly.
///
/// Terminal input is hidden when inputting a password
async fn get_password() -> Result<Zeroizing<String>, std::io::Error> {
    eprintln!("Passwords will be hidden for security.");
    loop {
        eprint!("Password: ");
        let password_one = from_tty_hidden().await?;

        eprint!("Confirm Password: ");
        let password_two = from_tty_hidden().await?;

        if password_one == password_two {
            return Ok(password_one);
        }

        eprintln!("Passwords do not match. Try again");
    }
}
