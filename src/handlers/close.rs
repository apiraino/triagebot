//! Allows to close an issue or a PR

use crate::{
    config::CloseConfig,
    errors::user_error,
    github::{Event, IssuesEvent, Label},
    handlers::Context,
};
use anyhow::Context as AnyhowContext;
use parser::command::close::CloseCommand;
use tracing as log;

// TODO: add more labels
const LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING: [&str; 3] =
    ["I-prioritize", "S-waiting-on-review", "S-waiting-on-author"];

pub(super) async fn handle_command(
    ctx: &Context,
    _config: &CloseConfig,
    event: &Event,
    _cmd: CloseCommand,
) -> anyhow::Result<()> {
    log::debug!("[handlers::close] handle_command");
    let issue = event.issue().unwrap();
    let is_team_member = ctx
        .team
        .is_team_member(&event.user().login)
        .await
        .unwrap_or(false);
    if !is_team_member {
        return user_error!("Only team members can close issues.");
    }
    issue.close(&ctx.github).await?;
    Ok(())
}

pub(super) async fn parse_input(
    _ctx: &Context,
    event: &IssuesEvent,
    _config: Option<&CloseConfig>,
) -> Result<Option<u64>, String> {
    log::debug!("[handlers::close] parse_input");
    // nothing to prepare or configure, the issue id is enough
    // TODO: this handler should be automatically enabled
    // let Some(config) = config else {
    //     return Ok(None);
    // };
    Ok(Some(event.issue.number))
}

pub(super) async fn handle_input(
    ctx: &Context,
    _config: &CloseConfig,
    event: &IssuesEvent,
    _input: u64,
) -> anyhow::Result<()> {
    log::debug!(
        "[handlers::close] handle_input for issue #{}",
        event.issue.number
    );
    let issue = &event.issue;
    let issue_labels: Vec<&str> = issue.labels.iter().map(|l| l.name.as_str()).collect();

    let labels_to_remove = issue_labels
        .iter()
        .copied()
        .filter(|label| LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING.contains(label))
        .map(|x| Label {
            name: x.to_string(),
        })
        .collect::<Vec<_>>();

    if !labels_to_remove.is_empty() {
        let _ = event
            .issue
            .remove_labels(&ctx.github, labels_to_remove)
            .await
            .context("failed to remove labels from the issue");
    }
    Ok(())
}
