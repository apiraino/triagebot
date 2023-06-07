#![allow(clippy::new_without_default)]

use anyhow::Context as _;
use futures::future::FutureExt;
use futures::StreamExt;
use hyper::{header, Body, Request, Response, Server, StatusCode};
use reqwest::Client;
use route_recognizer::Router;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::io::AsyncReadExt;
use tokio::{task, time};
use tokio_postgres::Client as DbClient;
use tower::{Service, ServiceExt};
use tracing as log;
use tracing::Instrument;
use triagebot::jobs::{jobs, JOB_PROCESSING_CADENCE_IN_SECS, JOB_SCHEDULING_CADENCE_IN_SECS};
use triagebot::{db, github, handlers::Context, notification_listing, payload, EventName};
use uuid::Uuid;

async fn handle_agenda_request(req: String) -> anyhow::Result<String> {
    if req == "/agenda/lang/triage" {
        return triagebot::agenda::lang().call().await;
    }
    if req == "/agenda/lang/planning" {
        return triagebot::agenda::lang_planning().call().await;
    }

    anyhow::bail!("Unknown agenda; see /agenda for index.")
}

#[derive(Deserialize)]
struct Config {
    people: People,
}

#[derive(Deserialize)]
struct People {
    members: Vec<String>,
}

async fn get_string_from_file(dest: &mut Vec<String>, s: &str) {
    let mut fd = tokio::fs::File::open(s)
        .await
        .unwrap_or_else(|err| panic!("Error opening file {}: {}", s, err));
    let mut contents = String::new();
    fd.read_to_string(&mut contents)
        .await
        .unwrap_or_else(|err| panic!("Error loading file {}: {}", s, err));
    contents = contents.trim_end().to_string();
    let mut config: Config = toml::from_str(&contents).unwrap();
    dest.append(&mut config.people.members);
}

#[derive(Debug, Serialize)]
pub struct ReviewCapacityUser {
    pub username: String,
    pub id: uuid::Uuid,
    pub user_id: i64,
    pub max_assigned_prs: Option<i32>,
    pub pto_date_start: Option<chrono::NaiveDate>,
    pub pto_date_end: Option<chrono::NaiveDate>,
    pub active: bool,
    pub allow_ping_after_days: Option<i32>,
    pub publish_prefs: bool,
}

const PREF_ALLOW_PING_AFTER_DAYS: i32 = 20;
const PREF_MAX_ASSIGNED_PRS: i32 = 5;

impl From<HashMap<String, String>> for ReviewCapacityUser {
    fn from(obj: HashMap<String, String>) -> Self {
        // if user set themselves as inactive
        // delete all their prefs
        let active = {
            let _o = obj.get("active");
            if _o.is_none() || _o.unwrap() == "no" {
                false
            } else {
                true
            }
        };

        let max_assigned_prs = if active {
            if let Some(x) = obj.get("max_assigned_prs") {
                Some(x.parse::<i32>().unwrap_or(PREF_MAX_ASSIGNED_PRS))
            } else {
                None
            }
        } else {
            None
        };

        let pto_date_start = if active {
            if let Some(x) = obj.get("pto_date_start") {
                Some(x.parse::<chrono::NaiveDate>().unwrap())
            } else {
                None
            }
        } else {
            None
        };

        let pto_date_end = if active {
            if let Some(x) = obj.get("pto_date_end") {
                Some(x.parse::<chrono::NaiveDate>().unwrap())
            } else {
                None
            }
        } else {
            None
        };

        let allow_ping_after_days = if active {
            if let Some(x) = obj.get("allow_ping_after_days") {
                Some(x.parse::<i32>().unwrap_or(PREF_ALLOW_PING_AFTER_DAYS))
            } else {
                None
            }
        } else {
            None
        };

        let publish_prefs = {
            let _obj = obj.get("publish_prefs");
            if _obj.is_none() || _obj.unwrap() == "no" {
                false
            } else {
                true
            }
        };

        let prefs = ReviewCapacityUser {
            username: obj.get("username").unwrap().to_string(),
            id: Uuid::parse_str(obj.get("id").unwrap()).unwrap(),
            user_id: obj.get("user_id").unwrap().parse::<i64>().unwrap(),
            max_assigned_prs,
            pto_date_start,
            pto_date_end,
            active,
            allow_ping_after_days,
            publish_prefs,
        };
        prefs
    }
}

impl From<tokio_postgres::row::Row> for ReviewCapacityUser {
    fn from(row: tokio_postgres::row::Row) -> Self {
        Self {
            username: row.get("username"),
            id: row.get("id"),
            user_id: row.get("user_id"),
            max_assigned_prs: row.get("max_assigned_prs"),
            pto_date_start: row.get("pto_date_start"),
            pto_date_end: row.get("pto_date_end"),
            active: row.get("active"),
            allow_ping_after_days: row.get("allow_ping_after_days"),
            publish_prefs: row.get("publish_prefs"),
        }
    }
}

pub async fn set_prefs(
    db: &DbClient,
    prefs: ReviewCapacityUser,
) -> anyhow::Result<ReviewCapacityUser> {
    let q = "
UPDATE review_capacity r
SET max_assigned_prs = $2, pto_date_start = $3, pto_date_end = $4, active = $5, allow_ping_after_days = $6, publish_prefs = $7
FROM users u
WHERE r.user_id=$1 AND u.user_id=r.user_id
RETURNING u.username, r.*";
    log::debug!("pref {:?}", prefs);
    log::debug!("SQL {:?}", q);
    let rec = db
        .query_one(
            q,
            &[
                &prefs.user_id,
                &prefs.max_assigned_prs,
                &prefs.pto_date_start,
                &prefs.pto_date_end,
                &prefs.active,
                &prefs.allow_ping_after_days,
                &prefs.publish_prefs,
            ],
        )
        .await
        .context("Update DB error")?;
    Ok(rec.into())
}

/// Get all review capacity preferences
/// me: sort "me" at the top of the list
/// is_admin: pull also not public profiles
pub async fn get_prefs(
    db: &DbClient,
    users: &mut Vec<String>,
    me: &str,
    is_admin: bool,
) -> Vec<ReviewCapacityUser> {
    let only_public_prefs = if !is_admin {
        " AND publish_prefs = true "
    } else {
        ""
    };
    let q = format!(
        "
SELECT username,review_capacity.*
FROM review_capacity
JOIN users on review_capacity.user_id=users.user_id
WHERE username = any($1) {}
ORDER BY case when username='{}' then 1 else 2 end, username;",
        only_public_prefs, me
    );

    let rows = db.query(&q, &[users]).await.unwrap();
    rows.into_iter()
        .map(|row| ReviewCapacityUser::from(row))
        .collect()
}

async fn serve_req(
    req: Request<Body>,
    ctx: Arc<Context>,
    mut agenda: impl Service<String, Response = String, Error = tower::BoxError>,
) -> Result<Response<Body>, hyper::Error> {
    log::info!("request = {:?}", req);
    let mut router = Router::new();
    router.add("/triage", "index".to_string());
    router.add("/triage/:owner/:repo", "pulls".to_string());
    let (req, body_stream) = req.into_parts();

    if let Ok(matcher) = router.recognize(req.uri.path()) {
        if matcher.handler().as_str() == "pulls" {
            let params = matcher.params();
            let owner = params.find("owner");
            let repo = params.find("repo");
            return triagebot::triage::pulls(ctx, owner.unwrap(), repo.unwrap()).await;
        } else {
            return triagebot::triage::index();
        }
    }

    if req.uri.path() == "/agenda" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(triagebot::agenda::INDEX))
            .unwrap());
    }
    if req.uri.path() == "/agenda/lang/triage" || req.uri.path() == "/agenda/lang/planning" {
        match agenda
            .ready()
            .await
            .expect("agenda keeps running")
            .call(req.uri.path().to_owned())
            .await
        {
            Ok(agenda) => {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(agenda))
                    .unwrap())
            }
            Err(err) => {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(err.to_string()))
                    .unwrap())
            }
        }
    }

    if req.uri.path() == "/" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("Triagebot is awaiting triage."))
            .unwrap());
    }
    if req.uri.path() == "/bors-commit-list" {
        let res = db::rustc_commits::get_commits_with_artifacts(&*ctx.db.get().await).await;
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("{:?}", e)))
                    .unwrap());
            }
        };
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&res).unwrap()))
            .unwrap());
    }
    if req.uri.path() == "/notifications" {
        if let Some(query) = req.uri.query() {
            let user = url::form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == "user");
            if let Some((_, name)) = user {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(
                        notification_listing::render(&ctx.db.get().await, &*name).await,
                    ))
                    .unwrap());
            }
        }

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(String::from(
                "Please provide `?user=<username>` query param on URL.",
            )))
            .unwrap());
    }
    if req.uri.path() == "/zulip-hook" {
        let mut c = body_stream;
        let mut payload = Vec::new();
        while let Some(chunk) = c.next().await {
            let chunk = chunk?;
            payload.extend_from_slice(&chunk);
        }

        let req = match serde_json::from_slice(&payload) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!(
                        "Did not send valid JSON request: {}",
                        e
                    )))
                    .unwrap());
            }
        };

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(triagebot::zulip::respond(&ctx, req).await))
            .unwrap());
    }
    if req.uri.path() == "/review-settings" {
        let mut body = serde_json::json!({});
        let db_client = ctx.db.get().await;

        if req.method == hyper::Method::POST {
            let mut c = body_stream;
            let mut payload = Vec::new();
            while let Some(chunk) = c.next().await {
                let chunk = chunk?;
                payload.extend_from_slice(&chunk);
            }
            let prefs = url::form_urlencoded::parse(payload.as_ref())
                .into_owned()
                .collect::<HashMap<String, String>>();
            log::debug!("prefs {:?}", prefs);

            // save changes
            let review_capacity = set_prefs(&db_client, prefs.into()).await.unwrap();
            log::debug!("Users from DB {:?}", review_capacity);
            body = serde_json::json!(&review_capacity);
        }

        if req.method == hyper::Method::GET {
            // TODO: infer these from the authentication
            let user = req
                .headers
                .get("Role")
                .ok_or_else(|| header::HeaderValue::from_static(""))
                .unwrap()
                .to_str()
                .unwrap_or("pnkfelix");
            let is_admin = user == "pnkfelix";
            log::debug!("user={}, is admin: {}", user, is_admin);

            // 1. download the TOML file(s) for that team, ex.:
            // https://raw.githubusercontent.com/rust-lang/team/master/teams/compiler.toml
            // https://raw.githubusercontent.com/rust-lang/team/master/teams/compiler-contributors.toml

            // 2. parse the TOML file and load all [people.members]
            let mut members = vec![];
            get_string_from_file(&mut members, "static/compiler.toml").await;
            get_string_from_file(&mut members, "static/compiler-contributors.toml").await;
            log::debug!("Members loaded {:?}", members);

            // 3. query the DB, pull all users that are members in the TOML file
            let review_capacity = get_prefs(&db_client, &mut members, user, is_admin).await;
            log::debug!("Users from DB {:?}", review_capacity);
            body = serde_json::json!(&review_capacity);
        }

        return Ok(Response::builder()
            .header("Content-Type", "application/json")
            .status(StatusCode::OK)
            .body(Body::from(body.to_string()))
            // .body(Body::from(triagebot::zulip::respond(&ctx, params).await))
            .unwrap());
    }
    if req.uri.path() != "/github-hook" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap());
    }
    if req.method != hyper::Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "POST")
            .body(Body::empty())
            .unwrap());
    }
    let event = if let Some(ev) = req.headers.get("X-GitHub-Event") {
        let ev = match ev.to_str().ok() {
            Some(v) => v,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("X-GitHub-Event header must be UTF-8 encoded"))
                    .unwrap());
            }
        };
        match ev.parse::<EventName>() {
            Ok(v) => v,
            Err(_) => unreachable!(),
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("X-GitHub-Event header must be set"))
            .unwrap());
    };
    log::debug!("event={}", event);
    let signature = if let Some(sig) = req.headers.get("X-Hub-Signature") {
        match sig.to_str().ok() {
            Some(v) => v,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("X-Hub-Signature header must be UTF-8 encoded"))
                    .unwrap());
            }
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("X-Hub-Signature header must be set"))
            .unwrap());
    };
    log::debug!("signature={}", signature);

    let mut c = body_stream;
    let mut payload = Vec::new();
    while let Some(chunk) = c.next().await {
        let chunk = chunk?;
        payload.extend_from_slice(&chunk);
    }

    if let Err(_) = payload::assert_signed(signature, &payload) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Wrong signature"))
            .unwrap());
    }
    let payload = match String::from_utf8(payload) {
        Ok(p) => p,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Payload must be UTF-8"))
                .unwrap());
        }
    };

    match triagebot::webhook(event, payload, &ctx).await {
        Ok(true) => Ok(Response::new(Body::from("processed request"))),
        Ok(false) => Ok(Response::new(Body::from("ignored request"))),
        Err(err) => {
            log::error!("request failed: {:?}", err);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("request failed: {:?}", err)))
                .unwrap())
        }
    }
}

async fn run_server(addr: SocketAddr) -> anyhow::Result<()> {
    let pool = db::ClientPool::new();
    db::run_migrations(&*pool.get().await)
        .await
        .context("database migrations")?;

    // spawning a background task that will schedule the jobs
    // every JOB_SCHEDULING_CADENCE_IN_SECS
    task::spawn(async move {
        loop {
            let res = task::spawn(async move {
                let pool = db::ClientPool::new();
                let mut interval =
                    time::interval(time::Duration::from_secs(JOB_SCHEDULING_CADENCE_IN_SECS));

                loop {
                    interval.tick().await;
                    db::schedule_jobs(&*pool.get().await, jobs())
                        .await
                        .context("database schedule jobs")
                        .unwrap();
                }
            });

            match res.await {
                Err(err) if err.is_panic() => {
                    /* handle panic in above task, re-launching */
                    tracing::trace!("schedule_jobs task died (error={})", err);
                }
                _ => unreachable!(),
            }
        }
    });

    let client = Client::new();
    let gh = github::GithubClient::new_with_default_token(client.clone());
    let oc = octocrab::OctocrabBuilder::new()
        .personal_token(github::default_token_from_env())
        .build()
        .expect("Failed to build octograb.");
    let ctx = Arc::new(Context {
        username: String::from("rustbot"),
        db: pool,
        github: gh,
        octocrab: oc,
    });

    // spawning a background task that will run the scheduled jobs
    // every JOB_PROCESSING_CADENCE_IN_SECS
    let ctx2 = ctx.clone();
    task::spawn(async move {
        loop {
            let ctx = ctx2.clone();
            let res = task::spawn(async move {
                let pool = db::ClientPool::new();
                let mut interval =
                    time::interval(time::Duration::from_secs(JOB_PROCESSING_CADENCE_IN_SECS));

                loop {
                    interval.tick().await;
                    db::run_scheduled_jobs(&ctx, &*pool.get().await)
                        .await
                        .context("run database scheduled jobs")
                        .unwrap();
                }
            });

            match res.await {
                Err(err) if err.is_panic() => {
                    /* handle panic in above task, re-launching */
                    tracing::trace!("run_scheduled_jobs task died (error={})", err);
                }
                _ => unreachable!(),
            }
        }
    });

    let agenda = tower::ServiceBuilder::new()
        .buffer(10)
        .layer_fn(|input| {
            tower::util::MapErr::new(
                tower::load_shed::LoadShed::new(tower::limit::RateLimit::new(
                    input,
                    tower::limit::rate::Rate::new(2, std::time::Duration::from_secs(60)),
                )),
                |_| anyhow::anyhow!("Rate limit of 2 request / 60 seconds exceeded"),
            )
        })
        .service_fn(handle_agenda_request);

    let svc = hyper::service::make_service_fn(move |_conn| {
        let ctx = ctx.clone();
        let agenda = agenda.clone();
        async move {
            Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                let uuid = uuid::Uuid::new_v4();
                let span = tracing::span!(tracing::Level::INFO, "request", ?uuid);
                serve_req(req, ctx.clone(), agenda.clone())
                    .map(move |mut resp| {
                        if let Ok(resp) = &mut resp {
                            resp.headers_mut()
                                .insert("X-Request-Id", uuid.to_string().parse().unwrap());
                        }
                        log::info!("response = {:?}", resp);
                        resp
                    })
                    .instrument(span)
            }))
        }
    });
    log::info!("Listening on http://{}", addr);

    let serve_future = Server::bind(&addr).serve(svc);

    serve_future.await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(std::env::var_os("DISABLE_COLOR").is_none())
        .try_init()
        .unwrap();

    let port = env::var("PORT")
        .ok()
        .map(|p| p.parse::<u16>().expect("parsed PORT"))
        .unwrap_or(8000);
    let addr = ([0, 0, 0, 0], port).into();
    if let Err(e) = run_server(addr).await {
        eprintln!("Failed to run server: {:?}", e);
    }
}
