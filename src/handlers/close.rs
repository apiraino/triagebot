//! Allows to close an issue or a PR

use crate::{
    config::CloseConfig,
    errors::user_error,
    github::{Event, IssuesEvent},
    handlers::Context,
    utils::contains_any,
};
use anyhow::Context as AnyhowContext;
use parser::command::close::CloseCommand;
use tracing as log;

const LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING: [&str; 1] = ["I-prioritize"];

pub(super) async fn handle_command(
    ctx: &Context,
    _config: &CloseConfig,
    event: &Event,
    _cmd: CloseCommand,
) -> anyhow::Result<()> {
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
    _event: &IssuesEvent,
    _config: Option<&CloseConfig>,
) -> Result<Option<u64>, String> {
    // log::debug!("[handlers::close] parse_input");
    // let Some(config) = config else {
    //     return Ok(None);
    // };
    // nothing to prepare, the issue id is enough
    Ok(None)
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

    // Check issue for labels to be removed
    // If none, return
    if !contains_any(&issue_labels, &LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING) {
        log::debug!(
            "Nothing to do, issue #{} has none of {:?}",
            issue.number,
            LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING
        );
        return Ok(());
    }

    let lbl = LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING.to_vec();

    // let labels_to_remove = contains_any(&issue_labels, &LABELS_TO_BE_REMOVED_ON_ISSUE_CLOSING);
    let labels_to_remove = issue_labels
        .iter()
        .zip(lbl)
        .map(|(a, b)| a - b)
        .collect::<Vec<_>>();

    let _ = event
        .issue
        .remove_labels(&ctx.github, labels_to_remove)
        .await
        .context("failed to remove labels from the issue");
    Ok(())
}
