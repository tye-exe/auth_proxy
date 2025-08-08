#![feature(assert_matches)]

mod cli;
mod configuration;
mod data;
mod database;
mod forward;

use crate::{cli::handle_user_input, configuration::Configuration, forward::handle_login};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpServer, middleware, web};
use awc::{Client, cookie::Key};
use std::{io, net::ToSocketAddrs as _};
use url::Url;

const LOGIN: &str = include_str!("../pages/login.html");

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config: Configuration = config::Config::builder()
        .add_source(config::File::with_name("./configuration.toml"))
        .add_source(config::Environment::with_prefix("AUTH"))
        .build()
        .and_then(|config| config.try_deserialize())
        .unwrap();

    let Configuration {
        target_host,
        target_port,
        listen_on,
        listen_port,
        sqlite_db,
        cookie_name,
    } = config;

    let sqlite_db = sqlite_db.create_if_missing(true);

    let pool = database::connect(sqlite_db)
        .await
        .expect("Unable to connect to database");

    handle_user_input(pool.clone()).await;

    let forward_socket_addr = (target_host.to_string(), target_port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addr| addr.next())
        .expect("given forwarding address was not valid");

    let forward_url = format!("http://{forward_socket_addr}");
    let forward_url = Url::parse(&forward_url).unwrap();

    log::info!(
        "starting HTTP server at http://{}:{}",
        listen_on,
        listen_port
    );

    log::info!("forwarding to {}", target_host);

    let secret_key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Client::default()))
            .app_data(web::Data::new(forward_url.clone()))
            .app_data(web::Data::new(pool.clone()))
            .wrap(middleware::Logger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_content_security(actix_session::config::CookieContentSecurity::Private)
                    .cookie_http_only(true)
                    .cookie_same_site(awc::cookie::SameSite::Strict)
                    .cookie_name(cookie_name.to_string())
                    .build(),
            )
            .service(handle_login)
            .default_service(web::to(crate::forward::forward))
    })
    .bind((listen_on, listen_port))?
    .workers(2)
    .run()
    .await
}
