use std::collections::HashSet;

use anyhow::bail;
use anyhow::Context as _;

use super::Context;
use crate::{
    config::Config,
    db::issue_data::IssueData,
    github::{Event, IssuesAction, IssuesEvent, Label, ReportedContentClassifiers},
};

#[cfg(test)]
use crate::github::GithubCommit;

mod issue_links;
mod modified_submodule;
mod no_mentions;
mod no_merges;
mod non_default_branch;

/// Key for the state in the database
const CHECK_COMMITS_WARNINGS_KEY: &str = "check-commits-warnings";

/// State stored in the database
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct CheckCommitsWarningsState {
    /// List of the last warnings in the most recent comment.
    last_warnings: Vec<String>,
    /// ID of the most recent warning comment.
    last_warned_comment: Option<String>,
    /// List of the last labels added.
    last_labels: Vec<String>,
}

pub(super) async fn handle(ctx: &Context, event: &Event, config: &Config) -> anyhow::Result<()> {
    let Event::Issue(event) = event else {
        return Ok(());
    };

    if !matches!(
        event.action,
        IssuesAction::Opened | IssuesAction::Synchronize | IssuesAction::ReadyForReview
    ) || !event.issue.is_pr()
    {
        return Ok(());
    }

    // Don't ping on rollups or draft PRs.
    if event.issue.title.starts_with("Rollup of") || event.issue.draft {
        return Ok(());
    }

    let Some(diff) = event.issue.diff(&ctx.github).await? else {
        bail!(
            "expected issue {} to be a PR, but the diff could not be determined",
            event.issue.number
        )
    };
    let commits = event.issue.commits(&ctx.github).await?;

    let mut warnings = Vec::new();
    let mut labels = Vec::new();

    // Compute the warnings
    if let Some(assign_config) = &config.assign {
        // For legacy reasons the non-default-branch and modifies-submodule warnings
        // are behind the `[assign]` config.

        if let Some(exceptions) = assign_config
            .warn_non_default_branch
            .enabled_and_exceptions()
        {
            warnings.extend(non_default_branch::non_default_branch(exceptions, event));
        }
        warnings.extend(modified_submodule::modifies_submodule(diff));
    }

    if let Some(no_mentions) = &config.no_mentions {
        warnings.extend(no_mentions::mentions_in_commits(no_mentions, &commits));
    }

    if let Some(issue_links) = &config.issue_links {
        warnings.extend(issue_links::issue_links_in_commits(issue_links, &commits));
    }

    if let Some(no_merges) = &config.no_merges {
        if let Some(warn) =
            no_merges::merges_in_commits(&event.issue.title, &event.repository, no_merges, &commits)
        {
            warnings.push(warn.0);
            labels.extend(warn.1);
        }
    }

    handle_warnings_and_labels(ctx, event, warnings, labels).await
}

// Add, hide or hide&add a comment with the warnings.
async fn handle_warnings_and_labels(
    ctx: &Context,
    event: &IssuesEvent,
    warnings: Vec<String>,
    labels: Vec<String>,
) -> anyhow::Result<()> {
    // Get the state of the warnings for this PR in the database.
    let mut db = ctx.db.get().await;
    let mut state: IssueData<'_, CheckCommitsWarningsState> =
        IssueData::load(&mut db, &event.issue, CHECK_COMMITS_WARNINGS_KEY).await?;

    // We only post a new comment when we haven't posted one with the same warnings before.
    if !warnings.is_empty() && state.data.last_warnings != warnings {
        // New set of warnings, let's post them.

        // Hide a previous warnings comment if there was one before printing the new ones.
        if let Some(last_warned_comment_id) = state.data.last_warned_comment {
            event
                .issue
                .hide_comment(
                    &ctx.github,
                    &last_warned_comment_id,
                    ReportedContentClassifiers::Resolved,
                )
                .await?;
        }

        let warning = warning_from_warnings(&warnings);
        let comment = event.issue.post_comment(&ctx.github, &warning).await?;

        state.data.last_warnings = warnings;
        state.data.last_warned_comment = Some(comment.node_id);
    } else if warnings.is_empty() {
        // No warnings to be shown, let's resolve a previous warnings comment, if there was one.
        if let Some(last_warned_comment_id) = state.data.last_warned_comment {
            event
                .issue
                .hide_comment(
                    &ctx.github,
                    &last_warned_comment_id,
                    ReportedContentClassifiers::Resolved,
                )
                .await?;

            state.data.last_warnings = Vec::new();
            state.data.last_warned_comment = None;
        }
    }

    // Handle the labels, add the new ones, remove the one no longer required, or don't do anything
    if !state.data.last_labels.is_empty() || !labels.is_empty() {
        let (labels_to_remove, labels_to_add) =
            calculate_label_changes(&state.data.last_labels, &labels);

        // Remove the labels no longer required
        if !labels_to_remove.is_empty() {
            for label in labels_to_remove {
                event
                    .issue
                    .remove_label(&ctx.github, &label)
                    .await
                    .context("failed to remove a label in check_commits")?;
            }
        }

        // Add the labels that are now required
        if !labels_to_add.is_empty() {
            event
                .issue
                .add_labels(
                    &ctx.github,
                    labels_to_add
                        .into_iter()
                        .map(|name| Label { name })
                        .collect(),
                )
                .await
                .context("failed to add labels in check_commits")?;
        }

        state.data.last_labels = labels;
    }

    // Save new state in the database
    state.save().await?;

    Ok(())
}

// Format the warnings for user consumption on Github
fn warning_from_warnings(warnings: &[String]) -> String {
    let warnings: Vec<_> = warnings
        .iter()
        .map(|warning| format!("* {warning}"))
        .collect();
    format!(":warning: **Warning** :warning:\n\n{}", warnings.join("\n"))
}

// Calculate the label changes
fn calculate_label_changes(
    previous: &Vec<String>,
    current: &Vec<String>,
) -> (Vec<String>, Vec<String>) {
    let previous_set: HashSet<String> = previous.into_iter().cloned().collect();
    let current_set: HashSet<String> = current.into_iter().cloned().collect();

    let removals = previous_set.difference(&current_set).cloned().collect();
    let additions = current_set.difference(&previous_set).cloned().collect();

    (removals, additions)
}

#[cfg(test)]
fn dummy_commit_from_body(sha: &str, body: &str) -> GithubCommit {
    use chrono::{DateTime, FixedOffset};

    GithubCommit {
        sha: sha.to_string(),
        commit: crate::github::GithubCommitCommitField {
            author: crate::github::GitUser {
                date: DateTime::<FixedOffset>::MIN_UTC.into(),
            },
            message: body.to_string(),
            tree: crate::github::GitCommitTree {
                sha: "60ff73dfdd81aa1e6737eb3dacdfd4a141f6e14d".to_string(),
            },
        },
        parents: vec![],
    }
}
