use std::io::stdin;

use clap::Parser;
use log::error;
use sqlx::sqlite::SqliteConnectOptions;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::database::connect;

#[derive(clap::Parser)]
enum User {
    Add,
}

#[derive(Error, Debug)]
enum ParseError {
    #[error(transparent)]
    StdinRead(#[from] std::io::Error),
    #[error(transparent)]
    InvalidArgument(#[from] clap::Error),
}

async fn handle_user_input(connection_options: SqliteConnectOptions) -> () {
    let connect = connect(connection_options).await;

    let (tx, mut rx) = mpsc::channel(2);
    read_stdin(tx);

    tokio::spawn(async move {
        loop {
            let Some(input) = rx.recv().await else {
                error!("Unable to process further command input");
                return;
            };

            let Ok(user) = User::try_parse_from(input.split_whitespace()) else {
                error!("Invalid command");
                continue;
            };

            todo!()
        }
    });
}

/// This function blocks. It should be spawned in a new thread.
fn parse() -> Result<(), ParseError> {
    let mut text = String::new();
    stdin().read_line(&mut text)?;

    let user = User::try_parse_from(text.split_whitespace())?;
    todo!()
}

fn read_stdin(tx: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        let mut lines = stdin().lines();
        loop {
            if let Some(Ok(line)) = lines.next() {
                if let Err(err) = tx.blocking_send(line) {
                    error!("Unable to handle input");
                };
            }
        }
    });
}
