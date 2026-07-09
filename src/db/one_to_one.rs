use crate::db::users::DbUser;
use crate::github::UserId;
use anyhow::Context;
use bytes::BytesMut;
use postgres_types::{FromSql, IsNull, ToSql, Type, to_sql_checked};
use std::collections::HashMap;
use std::error::Error;

/// Register a new 1:1 meeting
pub async fn insert_meeting(
    db: &tokio_postgres::Client,
    primary_: UserId,
    secondary: UserId,
    notes: String,
) -> anyhow::Result<u64, anyhow::Error> {
    // We need to have the user stored in the DB to have a valid FK link in review_prefs
    // record_username(db, user.id, &user.login).await?;

    let query = "
INSERT INTO one_to_one(primary_, secondary, created_at, notes)
VALUES ($1, $2, TODAY, $4)";

    let res = db
        .execute(query, &[&(primary_ as i64), &(secondary as i64), &notes])
        .await
        .context("Error upserting user review preferences")?;
    Ok(res)
}

// TODO
pub struct Meeting {
    primary_: String,
    secondary: String,
    created_at: String,
    notes: String,
}

/// Get 1:1 meetings
pub async fn get_meetings(
    db: &tokio_postgres::Client,
    primary_: UserId,
    secondary: UserId,
    team_name: String,
) -> anyhow::Result<Vec<Meeting>> {
    let query = r#"
SELECT * FROM one_to_one
JOIN teams ON teams.member == secondary
WHERE
  (primary_ == $1 OR primary_ == $2) AND
  teams.name = $3
ORDER BY date ASC
"#;

    let rows = db
        .query(
            query,
            &[&(primary_ as i64), &(secondary as i64), &team_name],
        )
        .await
        .context("Error retrieving global and team review preferences")?;

    let mut meetings = vec![];
    for row in rows {
        meetings.push(Meeting {
            primary_: row.get("primary_"),
            secondary: row.get("secondary"),
            created_at: row.get("created_at"),
            notes: row.get("notes"),
        });
    }
    Ok(meetings)
}
