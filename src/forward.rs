use std::time::Duration;

use crate::{
    LOGIN,
    data::{AuthToken, Login, Stage, UserState},
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

/// Forwards the request from a user with a token to the backend service.
/// If the token is invalid an error is returned.
async fn forward(
    req: HttpRequest,
    token: AuthToken,
    payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    forward_to: web::Data<Url>,
    client: web::Data<Client>,
    pool: web::Data<SqlitePool>,
    session: Session,
) -> Result<HttpResponse, Error> {
    if !database::valid_token(&pool, token).await? {
        session
            .remove(AUTH_TOKEN)
            .expect("There was not an auth token to remove");
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

pub async fn catch_all(
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

    forward(
        req, token, payload, peer_addr, forward_to, client, pool, session,
    )
    .await
}

#[post("/login")]
pub async fn handle_login(
    req: HttpRequest,
    session: Session,
    form: web::Form<Login>,
    pool: web::Data<SqlitePool>,
    // For forwarding
    payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    forward_to: web::Data<Url>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    dbg!("Login: {}", &session.entries());

    if let Some(token) = session.get(AUTH_TOKEN).expect("Able to deseralise token") {
        return forward(
            req, token, payload, peer_addr, forward_to, client, pool, session,
        )
        .await;
    }

    let user_id = get_user(&pool, form.0).await.map(|user| user.id())?;

    let mut rng = ChaCha12Rng::from_os_rng();
    let token = generate_token(&pool, &mut rng, user_id, Duration::from_secs(2000)).await?;
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

    let path = user.path().to_string();
    let user = user.set_stage(Stage::Authenticated);
    session
        .insert(USER_STATE, user)
        .expect("Able to insert state");

    Ok(Redirect::to(path)
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
    use awc::body::{self, MessageBody};
    use sqlx::sqlite::SqliteConnectOptions;
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

        assert_eq!(response.status().as_u16(), 303);

        let value = response
            .response()
            .cookies()
            .next()
            .expect("One cookie exists");
        let value = value.value();

        assert!(value.contains(r#"user_state":"{\"path\":\"/\",\"stage\":\"Authenticated"#));
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

    #[sqlx::test]
    async fn redirects_authenticated(pool: SqlitePool) {
        // Run the test on a local task.
        // Wiremock requires it.
        tokio::task::LocalSet::new()
            .run_until(async move {
                // `spawn_local` ensures that the future is spawned on the local
                // task set.
                tokio::task::spawn_local(async move {
                    use wiremock::matchers::{method, path};
                    let mock_server = MockServer::start().await;

                    Mock::given(method("GET"))
                        .and(path("/"))
                        .respond_with(ResponseTemplate::new(200).set_body_string("You did it!"))
                        .mount(&mock_server)
                        .await;

                    let login = Login::new("test", "abc");

                    database::add_user(&pool, "test", "abc").await.unwrap();

                    let p = pool.clone();
                    let app = crate::get_app!(p, &mock_server.uri());
                    let app = init_service(app()).await;

                    // Exit early in case of unexpected
                    let request = TestRequest::get().peer_addr(PEER_ADDR).to_request();
                    let response = call_service(&app, request).await;
                    assert_eq!(response.status(), 200);

                    // Authenticate
                    let request = TestRequest::post()
                        .uri("/login")
                        .set_form(login.clone())
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

                    // Send request to private service
                    let request = TestRequest::get()
                        .uri(
                            response
                                .response()
                                .headers()
                                .get("Location")
                                .expect("Location header in redirect")
                                .to_str()
                                .unwrap(),
                        )
                        .cookie(
                            response
                                .response()
                                .cookies()
                                .next()
                                .expect("One cookie exists"),
                        )
                        .peer_addr(PEER_ADDR)
                        .to_request();

                    let response = call_service(&app, request).await;

                    let body = response.into_body();
                    let bytes = body::to_bytes(body)
                        .await
                        .expect("Able to get body content");

                    assert_eq!(bytes, web::Bytes::from_static(b"You did it!"));
                })
                .await
                .unwrap();
            })
            .await;
    }

    /// Creates the [`App`] used for testing.
    ///
    /// This is a macro due to:
    /// - The type of [`App`] being heavily dependent on functions executed while configuring it.
    /// - The returned [`App`] needing to be a type of closure.
    #[macro_export]
    macro_rules! get_app {
        ($pool:expr, $url:expr) => {{
            #[cfg(not(test))]
            compile_error!(
                "'get_app!' is only to be used in testing, as it DOES NOT store cookie data securely."
            );

            use actix_session::{SessionMiddleware, storage::CookieSessionStore};
            // use actix_web::middleware;
            use url::Url;

            let url = Url::parse($url).unwrap();

            move || {
                actix_web::App::new()
                    .app_data(web::Data::new(Client::default()))
                    .app_data(web::Data::new(url.clone()))
                    .app_data(web::Data::new($pool.clone()))
                    // .wrap(middleware::Logger::default())
                    .wrap(
                        SessionMiddleware::builder(
                            CookieSessionStore::default(),
                            awc::cookie::Key::from(&std::array::from_fn::<u8, 64, _>(|_| 0)),
                        )
                        .cookie_content_security(
                            // To aid in testing
                            actix_session::config::CookieContentSecurity::Signed,
                        )
                        .cookie_http_only(true)
                        .cookie_same_site(awc::cookie::SameSite::Strict)
                        .build(),
                    )
                    .service(crate::forward::handle_login)
                    .default_service(web::to(crate::forward::catch_all))
            }
        }};
        ($pool:expr) => {{ crate::get_app!($pool, "http://example.com") }};
    }
}
