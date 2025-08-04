use std::time::Duration;

use crate::{
    LOGIN,
    data::{AuthToken, Login, UserState},
    database::{self, GetUserError, generate_token, get_user},
};
use actix_session::Session;
use actix_web::{
    HttpRequest, HttpResponse, Responder,
    dev::PeerAddr,
    post,
    web::{self, Redirect},
};
use awc::{Client, error::SendRequestError, http::StatusCode};
use rand::SeedableRng as _;
use rand_chacha::ChaCha12Rng;
use sqlx::SqlitePool;
use url::Url;

const AUTH_TOKEN: &str = "auth_token";
const USER_STATE: &str = "user_state";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unable to connect to database")]
    Database(#[from] sqlx::Error),
    #[error("Invalid login details")]
    InvalidLogin,
    #[error("Unable to make request to upstream: {0}")]
    UpstreamError(#[from] SendRequestError),
}

impl From<GetUserError> for Error {
    fn from(value: GetUserError) -> Self {
        match value {
            GetUserError::DatabaseError(error) => Self::Database(error),
            GetUserError::NonExistent => Self::InvalidLogin,
        }
    }
}

impl actix_web::error::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InvalidLogin => StatusCode::UNAUTHORIZED,
            Error::UpstreamError(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

pub async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    forward_to: web::Data<Url>,
    client: web::Data<Client>,
    pool: web::Data<SqlitePool>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let Some(token) = session
        .get::<AuthToken>(AUTH_TOKEN)
        .expect("Able to deseralise token")
    else {
        session
            .insert(USER_STATE, UserState::new(req.path().into()))
            .expect("Unable to seralise user state");
        return Ok(HttpResponse::Ok().body(LOGIN));
    };

    if !database::valid_token(&pool, token).await? {
        session
            .insert(USER_STATE, UserState::new(req.path().into()))
            .expect("Unable to seralise user state");
        return Ok(HttpResponse::Unauthorized().body(LOGIN));
    };

    let mut new_url = (**forward_to).clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());

    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress();

    // TODO: This forwarded implementation is incomplete as it only handles the unofficial
    // X-Forwarded-For header but not the official Forwarded one.
    let forwarded_req = match peer_addr {
        Some(PeerAddr(addr)) => {
            forwarded_req.insert_header(("x-forwarded-for", addr.ip().to_string()))
        }
        None => forwarded_req,
    };

    let res = forwarded_req.send_stream(payload).await?;

    let mut client_resp = HttpResponse::build(res.status());
    // Remove `Connection` as per
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    Ok(client_resp.streaming(res))
}

#[post("/login")]
pub async fn handle_login(
    req: HttpRequest,
    session: Session,
    form: web::Form<Login>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, Error> {
    let user_id = get_user(&pool, form.0).await.map(|user| user.id())?;

    let mut rng = ChaCha12Rng::from_os_rng();
    let token = generate_token(&pool, &mut rng, user_id, Duration::default()).await?;
    session
        .insert(AUTH_TOKEN, token)
        .expect("Unable to seralise token");

    let Some(user) = session
        .get::<UserState>(USER_STATE)
        .expect("Unable to deseralise user data")
    else {
        session.purge();
        return Ok(HttpResponse::BadRequest().into());
    };

    Ok(Redirect::to(user.path().to_string())
        .see_other()
        .respond_to(&req)
        .map_into_boxed_body())
}

#[cfg(test)]
mod tests {
    use std::{
        assert_matches::assert_matches,
        net::{Ipv4Addr, SocketAddr},
    };

    use super::*;
    use crate::database::{self};
    use actix_web::test::{TestRequest, call_service, init_service};
    use awc::body::MessageBody;
    use sqlx::sqlite::SqliteConnectOptions;

    const PEER_ADDR: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);

    #[actix_web::test]
    async fn anonymous() {
        let pool = database::connect(SqliteConnectOptions::new().in_memory(true))
            .await
            .unwrap();

        let app = crate::get_app!(pool);
        let app = init_service(app()).await;

        let request = TestRequest::get().to_request();
        let response = call_service(&app, request).await;

        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().try_into_bytes().unwrap(), LOGIN);
    }

    #[actix_web::test]
    async fn anonymous_path() {
        let pool = database::connect(SqliteConnectOptions::new().in_memory(true))
            .await
            .unwrap();

        let app = crate::get_app!(pool);
        let app = init_service(app()).await;

        let request = TestRequest::get().uri("/thingies").to_request();
        let response = call_service(&app, request).await;

        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().try_into_bytes().unwrap(), LOGIN);
    }

    // #[sqlx::test]
    // async fn logged_in(pool: SqlitePool) {
    //     database::add_user(&pool, "test", "abc").await.unwrap();
    //     let user_id = database::get_user(&pool, Login::new("test", "abc"))
    //         .await
    //         .map(|user| user.id())
    //         .expect("Able to get user");

    //     let mut rng = ChaCha12Rng::from_seed(Default::default());
    //     generate_token(&pool, &mut rng, user_id, Utc::now().naive_utc())
    //         .await
    //         .expect("Able to generate token");

    //     let p = pool.clone();
    //     let app = crate::get_app!(p);
    //     let app = init_service(app()).await;

    //     // Exit early in case of unexpected
    //     let request = TestRequest::get().peer_addr(PEER_ADDR).to_request();
    //     let response = call_service(&app, request).await;
    //     assert_eq!(response.status(), 200);

    //     let request = TestRequest::post()
    //         .uri("/login")
    //         .set_form(Login::new("test", "abc"))
    //         .peer_addr(PEER_ADDR)
    //         .cookie(
    //             response
    //                 .response()
    //                 .cookies()
    //                 .next()
    //                 .expect("One cookie exists"),
    //         )
    //         .to_request();
    //     let response = call_service(&app, request).await;

    //     assert_matches!(response.status().as_u16(), 303);
    // }

    #[sqlx::test]
    async fn handle_login(pool: SqlitePool) {
        database::add_user(&pool, "test", "abc").await.unwrap();

        let p = pool.clone();
        let app = crate::get_app!(p);
        let app = init_service(app()).await;

        // Exit early in case of unexpected
        let request = TestRequest::get().peer_addr(PEER_ADDR).to_request();
        let response = call_service(&app, request).await;
        assert_eq!(response.status(), 200);

        let request = TestRequest::post()
            .uri("/login")
            .set_form(Login::new("test", "abc"))
            .peer_addr(PEER_ADDR)
            .cookie(
                response
                    .response()
                    .cookies()
                    .next()
                    .expect("One cookie exists"),
            )
            .to_request();
        let response = call_service(&app, request).await;

        assert_matches!(response.status().as_u16(), 303);
    }

    #[sqlx::test]
    async fn login_redirects(pool: SqlitePool) {
        database::add_user(&pool, "test", "abc").await.unwrap();

        let p = pool.clone();
        let app = crate::get_app!(p);
        let app = init_service(app()).await;

        // Exit early in case of unexpected
        let request = TestRequest::get()
            .uri("/cat_vids")
            .peer_addr(PEER_ADDR)
            .to_request();
        let response = call_service(&app, request).await;
        assert_eq!(response.status(), 200);

        let request = TestRequest::post()
            .uri("/login")
            .set_form(Login::new("test", "abc"))
            .peer_addr(PEER_ADDR)
            .cookie(
                response
                    .response()
                    .cookies()
                    .next()
                    .expect("One cookie exists"),
            )
            .to_request();
        let response = call_service(&app, request).await;

        assert_eq!(response.status().as_u16(), 303);
        assert_eq!(
            response
                .headers()
                .get("Location")
                .expect("Location header must exist"),
            "/cat_vids"
        );
    }

    #[sqlx::test]
    async fn login_wrong_identity(pool: SqlitePool) {
        database::add_user(&pool, "test", "abc").await.unwrap();

        let p = pool.clone();
        let app = crate::get_app!(p);
        let app = init_service(app()).await;

        // Exit early in case of unexpected
        let request = TestRequest::get().peer_addr(PEER_ADDR).to_request();
        let response = call_service(&app, request).await;
        assert_eq!(response.status(), 200);

        let request = TestRequest::post()
            .uri("/login")
            .set_form(Login::new("wrong", "abc"))
            .peer_addr(PEER_ADDR)
            .cookie(
                response
                    .response()
                    .cookies()
                    .next()
                    .expect("One cookie exists"),
            )
            .to_request();
        let response = call_service(&app, request).await;

        assert_eq!(response.status().as_u16(), 401);
    }

    #[sqlx::test]
    async fn login_wrong_password(pool: SqlitePool) {
        database::add_user(&pool, "test", "abc").await.unwrap();

        let p = pool.clone();
        let app = crate::get_app!(p);
        let app = init_service(app()).await;

        // Exit early in case of unexpected
        let request = TestRequest::get().peer_addr(PEER_ADDR).to_request();
        let response = call_service(&app, request).await;
        assert_eq!(response.status(), 200);

        let request = TestRequest::post()
            .uri("/login")
            .set_form(Login::new("test", "wrong"))
            .peer_addr(PEER_ADDR)
            .cookie(
                response
                    .response()
                    .cookies()
                    .next()
                    .expect("One cookie exists"),
            )
            .to_request();
        let response = call_service(&app, request).await;

        assert_eq!(response.status().as_u16(), 401);
    }

    /// Creates the [`App`] used for testing.
    ///
    /// This is a macro due to:
    /// - The type of [`App`] being heavily dependent on functions executed while configuring it.
    /// - The returned [`App`] needing to be a type of closure.
    #[macro_export]
    macro_rules! get_app {
        ($pool:expr) => {{
            use actix_session::{SessionMiddleware, storage::CookieSessionStore};
            // use actix_web::middleware;
            use url::Url;

            let url = Url::parse("http://example.com").unwrap();

            move || {
                actix_web::App::new()
                    .app_data(web::Data::new(Client::default()))
                    .app_data(web::Data::new(url.clone()))
                    .app_data(web::Data::new($pool.clone()))
                    // .wrap(middleware::Logger::default())
                    .wrap(
                        SessionMiddleware::builder(
                            CookieSessionStore::default(),
                            awc::cookie::Key::generate(),
                        )
                        .cookie_content_security(
                            actix_session::config::CookieContentSecurity::Private,
                        )
                        .cookie_http_only(true)
                        .cookie_same_site(awc::cookie::SameSite::Strict)
                        .build(),
                    )
                    .service(crate::forward::handle_login)
                    .default_service(web::to(crate::forward::forward))
            }
        }};
    }
}
