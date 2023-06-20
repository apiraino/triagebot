use crate::{
    config::ReviewPrefsConfig,
    github::{IssuesAction, IssuesEvent},
    handlers::Context,
    ReviewCapacityUser,
};
use anyhow::Context as _;
use tokio_postgres::Client as DbClient;
use tracing as log;

// This module updates the PR work queue of reviewers
// - Increment by 1 the work queue of the user when a PR is assigned
// - Decrement by 1 the work queue of the user when a PR is unassigned or closed
// - Else?

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
/// - me: sort this user at the top of the list
/// - is_admin: pull also profiles marked as not public
pub async fn get_prefs(
    db: &DbClient,
    users: &mut Vec<String>,
    me: &str,
    is_admin: bool,
) -> Vec<ReviewCapacityUser> {
    let q = format!(
        "
SELECT username,review_capacity.*
FROM review_capacity
JOIN users on review_capacity.user_id=users.user_id
WHERE username = any($1)
ORDER BY case when username='{}' then 1 else 2 end, username;",
        me
    );

    let rows = db.query(&q, &[users]).await.unwrap();
    rows.into_iter()
        .filter_map(|row| {
            let rec = ReviewCapacityUser::from(row);
            if is_admin || rec.username == me || rec.publish_prefs == true {
                Some(rec)
            } else {
                None
            }
        })
        .collect()
}

pub async fn get_reviewer_prefs_by_nick(
    db: &DbClient,
    gh_nick: &str,
) -> anyhow::Result<ReviewCapacityUser> {
    let q = format!(
        "
SELECT username, r.*
FROM review_capacity r
JOIN users on users.user_id=r.user_id
AND username='{}'",
        gh_nick
    );
    log::debug!("get reviewer by nick {:?}", gh_nick);
    log::debug!("SQL {:?}", q);
    let rec = db.query_one(&q, &[]).await.context("Select DB error")?;
    Ok(rec.into())
}

pub async fn get_reviewer_prefs_by_capacity(db: &DbClient) -> anyhow::Result<ReviewCapacityUser> {
    let q = "
SELECT username, r.*, sum(r.max_assigned_prs - r.cur_assigned_prs) as avail_slots
FROM review_capacity r
JOIN users on users.user_id=r.user_id
WHERE active = true
AND current_date NOT BETWEEN pto_date_start AND pto_date_end
AND cur_assigned_prs < max_assigned_prs
GROUP BY username, r.id
ORDER BY avail_slots DESC
LIMIT 1";
    log::debug!("get reviewers by capacity");
    log::debug!("SQL {:?}", q);
    let rec = db.query_one(q, &[]).await.context("Select DB error")?;
    Ok(rec.into())
}

pub(super) struct ReviewPrefsInput {}

pub(super) async fn parse_input(
    _ctx: &Context,
    event: &IssuesEvent,
    config: Option<&ReviewPrefsConfig>,
) -> Result<Option<ReviewPrefsInput>, String> {
    log::debug!("[review_prefs] parse_input");
    let _config = match config {
        Some(config) => config,
        None => return Ok(None),
    };

    log::debug!(
        "[review_prefs] now matching the action for event {:?}",
        event
    );
    match event.action {
        IssuesAction::Assigned => {
            log::debug!("[review_prefs] PR assigned: Will add to work queue");
            Ok(None)
        }
        IssuesAction::Unassigned | IssuesAction::Closed => {
            // TODO: find a way to decrease the work queue of the assignee of this PR.
            // event.issue.user.login is empty so we don't know who was the assignee of this PR
            // see their docs: https://docs.github.com/en/webhooks-and-events/webhooks/webhook-events-and-payloads?actionType=unassigned#pull_request
            log::debug!("[review_prefs] PR unassigned: Will remove from work queue");
            Ok(None)
        }
        _ => {
            log::debug!("[review_prefs] Other action on PR {:?}", event.action);
            Ok(None)
        }
    }
}

pub async fn update_assigned_prs(
    db: &DbClient,
    user_id: i64,
    cur_assigned_prs: i32,
) -> anyhow::Result<ReviewCapacityUser> {
    let q = "
UPDATE review_capacity r
SET cur_assigned_prs = $2
FROM users u
WHERE r.user_id=$1 AND u.user_id=r.user_id
RETURNING u.username, r.*";
    log::debug!("SQL {:?}", q);
    let rec = db
        .query_one(q, &[&user_id, &cur_assigned_prs])
        .await
        .context("Update DB error")?;
    Ok(rec.into())
}

pub(super) async fn handle_input<'a>(
    ctx: &Context,
    _config: &ReviewPrefsConfig,
    event: &IssuesEvent,
    _inputs: ReviewPrefsInput,
) -> anyhow::Result<()> {
    let db_client = ctx.db.get().await;

    if event.issue.user.login.is_empty() {
        todo!("When unassigning a PR, we don't receive the assignee that is removed so we don't know who was unassigned this PR");
    }

    let prefs = get_reviewer_prefs_by_nick(&db_client, &event.issue.user.login)
        .await
        .unwrap();

    let amount_change = match event.action {
        IssuesAction::Assigned => prefs.cur_assigned_prs.unwrap() + 1,
        IssuesAction::Unassigned | IssuesAction::Closed => prefs.cur_assigned_prs.unwrap() - 1,
        _ => 0,
    };

    let _pref_updated = update_assigned_prs(&db_client, prefs.user_id, amount_change)
        .await
        .unwrap();

    Ok(())
}
