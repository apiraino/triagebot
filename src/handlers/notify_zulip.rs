//! Handles sending messages to the Zulip chat instance.
//!
//! Configured in [notify-zulip.*] sections
//!

use crate::config::Config;
use crate::github::{GitHubUser, Issue, IssueCommentEvent};
use crate::zulip::api::Recipient;
use crate::zulip::{Mention, PingMode, format_zulip_mention};
use crate::{
    config::{NotifyZulipConfig, NotifyZulipLabelConfig, NotifyZulipTablesConfig},
    github::{IssuesAction, IssuesEvent, Label},
    handlers::Context,
};
use futures::future::join_all;
use octocrab::models::issues::IssueStateReason;
use tracing as log;

// TODO: what is this?
#[derive(Debug)]
pub(super) struct NotifyZulipInput {
    /// Type of the Zulip notification. Remaps the corresponding GitHub IssueAction.
    notification_type: NotificationType,
    /// Label that triggered this notification.
    ///
    /// For example, if an `I-prioritize` issue is closed,
    /// this field will be `I-prioritize`.
    label: Label,
    /// List of strings for tables such as [notify-zulip."beta-nominated"]
    /// and/or [notify-zulip."beta-nominated".compiler]
    include_config_names: Vec<String>,
}

#[derive(Debug)]
pub(super) enum NotificationType {
    Labeled,
    Unlabeled,
    Closed(CloseKind),
    Reopened,
}

/// A successful close is a merged pull request or an issue closed as completed.
/// Issues and pull requests otherwise share [`CloseKind::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CloseKind {
    Success,
    Other,
}

fn close_kind(issue: &Issue) -> CloseKind {
    let success = if issue.is_pr() {
        issue.merged_at.is_some()
    } else {
        matches!(issue.state_reason, Some(IssueStateReason::Completed))
    };
    if success {
        CloseKind::Success
    } else {
        CloseKind::Other
    }
}

/// `message_on_close_success` is used for a successful close when it is set.
/// Every other close, and a successful close with no success message, uses
/// `message_on_close`.
fn close_messages(config: &NotifyZulipLabelConfig, kind: CloseKind) -> &[String] {
    if kind == CloseKind::Success && !config.messages_on_close_success.is_empty() {
        &config.messages_on_close_success
    } else {
        &config.messages_on_close
    }
}

pub(super) async fn parse_input(
    _ctx: &Context,
    event: &IssuesEvent,
    config: Option<&NotifyZulipConfig>,
) -> Result<Option<Vec<NotifyZulipInput>>, String> {
    let Some(config) = config else {
        return Ok(None);
    };
    match &event.action {
        IssuesAction::Labeled { label } | IssuesAction::Unlabeled { label: Some(label) } => {
            let applied_label = label.clone();
            Ok(config
                .labels
                .get(&applied_label.name)
                .and_then(|label_config| {
                    parse_label_change_input(event, applied_label, label_config)
                })
                .map(|input| vec![input]))
        }
        // We skip the "issue opened" webhook: it would be redundant with "labeled"
        // and cause the event to be handled twice.
        //
        // https://rust-lang.zulipchat.com/#narrow/channel/224082-triagebot/topic/Duplicate.20messages.20for.20Zulip.20notifications.3F/with/630650250
        IssuesAction::Closed | IssuesAction::Reopened => {
            Ok(Some(parse_close_reopen_input(event, config)))
        }
        _ => Ok(None),
    }
}

fn parse_label_change_input(
    event: &IssuesEvent,
    label: Label,
    config: &NotifyZulipTablesConfig,
) -> Option<NotifyZulipInput> {
    let mut include_config_names: Vec<String> = vec![];

    for (name, label_config) in &config.subtables {
        if has_all_required_labels(&event.issue, label_config) {
            match event.action {
                IssuesAction::Labeled { .. } if !label_config.messages_on_add.is_empty() => {
                    include_config_names.push(name.to_string());
                }
                IssuesAction::Unlabeled { .. } if !label_config.messages_on_remove.is_empty() => {
                    include_config_names.push(name.to_string());
                }
                _ => (),
            }
        }
    }

    if include_config_names.is_empty() {
        // It seems that there is no match between this event and any notify-zulip config, ignore this event
        return None;
    }

    match event.action {
        IssuesAction::Labeled { .. } => Some(NotifyZulipInput {
            notification_type: NotificationType::Labeled,
            label,
            include_config_names,
        }),
        IssuesAction::Unlabeled { .. } => Some(NotifyZulipInput {
            notification_type: NotificationType::Unlabeled,
            label,
            include_config_names,
        }),
        _ => None,
    }
}

fn parse_close_reopen_input(
    event: &IssuesEvent,
    global_config: &NotifyZulipConfig,
) -> Vec<NotifyZulipInput> {
    let close_kind = close_kind(&event.issue);
    event
        .issue
        .labels
        .iter()
        .cloned()
        .filter_map(|label| {
            global_config
                .labels
                .get(&label.name)
                .map(|config| (label, config))
        })
        .filter_map(|(label, config)| {
            let mut include_config_names: Vec<String> = vec![];

            for (name, label_config) in &config.subtables {
                if has_all_required_labels(&event.issue, label_config) {
                    match event.action {
                        IssuesAction::Closed
                            if !close_messages(label_config, close_kind).is_empty() =>
                        {
                            include_config_names.push(name.to_string());
                        }
                        IssuesAction::Reopened if !label_config.messages_on_reopen.is_empty() => {
                            include_config_names.push(name.to_string());
                        }
                        _ => (),
                    }
                }
            }

            if include_config_names.is_empty() {
                // It seems that there is no match between this event and any notify-zulip config, ignore this event
                return None;
            }

            match event.action {
                IssuesAction::Closed => Some(NotifyZulipInput {
                    notification_type: NotificationType::Closed(close_kind),
                    label,
                    include_config_names,
                }),
                IssuesAction::Reopened => Some(NotifyZulipInput {
                    notification_type: NotificationType::Reopened,
                    label,
                    include_config_names,
                }),
                _ => None,
            }
        })
        .collect()
}

fn has_all_required_labels(issue: &Issue, config: &NotifyZulipLabelConfig) -> bool {
    for req_label in &config.required_labels {
        let pattern = match globset::Glob::new(req_label) {
            Ok(pattern) => pattern,
            Err(err) => {
                log::error!("Invalid glob pattern: {err}");
                continue;
            }
        };
        let matcher = pattern.compile_matcher();
        if !issue.labels().iter().any(|l| matcher.is_match(&l.name)) {
            return false;
        }
    }

    true
}

pub(super) async fn handle_input(
    ctx: &Context,
    config: &NotifyZulipConfig,
    event: &IssuesEvent,
    inputs: Vec<NotifyZulipInput>,
) -> anyhow::Result<()> {
    for input in inputs {
        log::debug!(
            "Searching in {:?} label name={}",
            &config.labels,
            &input.label.name
        );
        // FIXME: why is there no "label name=T-compiler"?
        //  {   "stable-accepted": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: stable-nominated", github_comment: None, messages_on_add: ["PR #{number} has been **accepted** for **stable** backport."], messages_on_remove: [], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler"] }} },

        //     "I-prioritize": NotifyZulipTablesConfig { subtables: {"": NotifyZulipLabelConfig { zulip_stream: 384059, topic: "#{number} {title}", github_comment: None, messages_on_add: ["Issue #{number} has been requested for prioritization.\n\n# [Procedure](https://forge.rust-lang.org/compiler/prioritization.html)\n- Priority?\n- Regression?\n- Notify people/groups?\n- Needs `I-{team}-nominated`?\n"], messages_on_remove: ["Issue #{number}'s prioritization request has been removed."], messages_on_close: ["Issue #{number} has been closed while requested for prioritization."], messages_on_close_success: [], messages_on_reopen: ["Issue #{number} has been reopened."], required_labels: [] }} },

        //     "beta-nominated": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: beta-nominated", github_comment: None, messages_on_add: ["PR #{number} \"{title}\" fixes a regression.\n{recipients} please evaluate nominating this PR for backport, thanks!\nThe following poll is a vibe-check and not binding.\n", "/poll Should #{number} be beta backported?\napprove\ndecline\ndon't know\n"], messages_on_remove: ["PR #{number}'s beta-nomination has been removed."], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler", "beta-nominated"] }} },

        //     "beta-accepted": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: beta-nominated", github_comment: None, messages_on_add: ["PR #{number} has been **accepted** for **beta** backport."], messages_on_remove: [], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler"] }} },

        //     "stable-nominated": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: stable-nominated", github_comment: None, messages_on_add: ["PR #{number} \"{title}\" fixes a regression.\n{recipients} please evaluate nominating this PR for backport, thanks!\nThe following poll is a vibe-check and not binding.\n", "/poll Should #{number} be stable backported?\napprove\ndecline\ndon't know\n"], messages_on_remove: ["PR #{number}'s stable-nomination has been removed."], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler", "stable-nominated", "!stable-accepted"] }}

        let tables_config = &config.labels[&input.label.name];
        log::debug!(
            "[handle_input] Iterating input type={:?} label={}, include_config_names={:?}, tables_config={:?}",
            input.notification_type,
            input.label.name,
            input.include_config_names,
            tables_config
        );

        // Get valid label configs
        let mut label_configs: Vec<&NotifyZulipLabelConfig> = vec![];
        for name in input.include_config_names {
            // TODO: figure out what is supposed in "name"
            label_configs.push(&tables_config.subtables[&name]);
        }

        log::debug!("[handle_input] label configs {:?}", label_configs);
        for label_config in label_configs {
            let config = label_config;

            let topic = &config.topic;
            let topic = topic.replace("{number}", &event.issue.number.to_string());
            let mut topic = topic.replace("{title}", &event.issue.title);
            // Truncate to 60 chars (a Zulip limitation)
            let mut chars = topic.char_indices().skip(59);
            if let (Some((len, _)), Some(_)) = (chars.next(), chars.next()) {
                topic.truncate(len);
                topic.push('…');
            }

            let msgs = match input.notification_type {
                NotificationType::Labeled => &config.messages_on_add,
                NotificationType::Unlabeled => &config.messages_on_remove,
                NotificationType::Closed(close_kind) => close_messages(config, close_kind),
                NotificationType::Reopened => &config.messages_on_reopen,
            };

            let github_comment = match input.notification_type {
                NotificationType::Labeled => &config.github_comment,
                NotificationType::Unlabeled
                | NotificationType::Closed(_)
                | NotificationType::Reopened => &None,
            };

            let recipient = Recipient::Stream {
                id: config.zulip_stream,
                topic: &topic,
            };

            // Issue/PR authors/reviewers will receive a mention if the template has `{recipients}`.
            let recipients = &mut event.issue.assignees.clone();
            recipients.push(event.issue.user.clone());

            // TODO: When going through this when a PR is approved
            // `msgs_send` can stay to zero because we don't send messages to GitHub
            let mut msgs_send = 0;

            for msg in msgs {
                let msg = msg.replace("{number}", &event.issue.number.to_string());
                let msg = msg.replace("{title}", &event.issue.title);
                let msg = replace_team_to_be_nominated(&event.issue.labels, msg);
                let msg = msg.replace("{recipients}", &get_zulip_ids(ctx, recipients).await);

                log::debug!("[handle_input] sending msg to Zulip {}", msg);
                let req = crate::zulip::MessageApiRequest {
                    recipient,
                    content: &msg,
                }
                .send(&ctx.zulip)
                .await;

                if let Err(err) = req {
                    log::error!("Failed to send notification to Zulip {err}");
                } else {
                    msgs_send += 1;
                }
            }

            if msgs_send > 0
                && let Some(github_comment) = &github_comment
            {
                let github_comment =
                    github_comment.replace("{zulip_topic_url}", &recipient.url(&ctx.zulip));

                if let Err(err) = event.issue.post_comment(&ctx.github, &github_comment).await {
                    log::error!("failed to post github notification comment {err}");
                }
            }
        }
    }

    Ok(())
}

/// Send a message on Zulip when a pull request fixing a P-high/P-critical regression is approved (see `handlers.rs`)
/// This is just a wrapper around handle_input() to remap a `IssueCommentEvent` into `IssueEvent`
// TODO: everything here should be parametized, remove all the hardcoded stuff!
pub(crate) async fn handle_pr_approved(
    ctx: &Context,
    event: &IssueCommentEvent,
    config: &Config,
) -> anyhow::Result<()> {
    // 2026-10-27T16:53:46.835578Z DEBUG request{request_id="a5945370-4b5b-4e62-9580-ef34b2e62fc5"}: triagebot::handlers::notify_zulip: [notify_zulip::handle_pr_approved] config Config { relabel: Some(RelabelConfig { allow_unauthenticated: [], aliases: {"alias": RelabelAliasConfig { add_labels: [], rem_labels: [] }} }), assign: None, ping: None, nominate: None, prioritize: None, major_change: None, lock: Some(LockConfig), close: None, autolabel: None, notify_zulip: Some(NotifyZulipConfig { labels: {"beta-nominated": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: beta-nominated", github_comment: None, messages_on_add: ["PR #{number} \"{title}\" fixes a regression.\n{recipients} please evaluate nominating this PR for backport, thanks!\nThe following poll is a vibe-check and not binding.\n", "/poll Should #{number} be beta backported?\napprove\ndecline\ndon't know\n"], messages_on_remove: ["PR #{number}'s beta-nomination has been removed."], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler", "beta-nominated"] }} }, "stable-accepted": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: stable-nominated", github_comment: None, messages_on_add: ["PR #{number} has been **accepted** for **stable** backport."], messages_on_remove: [], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler"] }} }, "stable-nominated": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: stable-nominated", github_comment: None, messages_on_add: ["PR #{number} \"{title}\" fixes a regression.\n{recipients} please evaluate nominating this PR for backport, thanks!\nThe following poll is a vibe-check and not binding.\n", "/poll Should #{number} be stable backported?\napprove\ndecline\ndon't know\n"], messages_on_remove: ["PR #{number}'s stable-nomination has been removed."], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler", "stable-nominated", "!stable-accepted"] }} }, "beta-accepted": NotifyZulipTablesConfig { subtables: {"compiler": NotifyZulipLabelConfig { zulip_stream: 554919, topic: "#{number}: beta-nominated", github_comment: None, messages_on_add: ["PR #{number} has been **accepted** for **beta** backport."], messages_on_remove: [], messages_on_close: [], messages_on_close_success: [], messages_on_reopen: [], required_labels: ["T-compiler"] }} }, "I-prioritize": NotifyZulipTablesConfig { subtables: {"": NotifyZulipLabelConfig { zulip_stream: 384059, topic: "#{number} {title}", github_comment: None, messages_on_add: ["Issue #{number} has been requested for prioritization.\n\n# [Procedure](https://forge.rust-lang.org/compiler/prioritization.html)\n- Priority?\n- Regression?\n- Notify people/groups?\n- Needs `I-{team}-nominated`?\n"], messages_on_remove: ["Issue #{number}'s prioritization request has been removed."], messages_on_close: ["Issue #{number} has been closed while requested for prioritization."], messages_on_close_success: [], messages_on_reopen: ["Issue #{number} has been reopened."], required_labels: [] }} }} }), github_releases: None, review_submitted: None, review_requested: None, shortcut: None, note: None, concern: None, mentions: None, no_merges: None, pr_tracking: None, transfer: None, merge: None, merge_conflicts: None, bot_pull_requests: None, rendered_link: None, large_pull_requests: None, issue_links: None, behind_upstream: None, skipped_workflow_runs: None, backport: Some(BackportConfig { configs: {"t-compiler-beta-backport": BackportRuleConfig { required_pr_labels: ["T-compiler"], required_issue_label: "regression-from-stable-to-beta", add_labels: ["beta-nominated"] }} }), range_diff: None, review_changes_since: None, view_all_comments_link: None }
    log::debug!("[notify_zulip::handle_pr_approved] config {:?}", &config);

    // event ReviewSubmitted
    log::debug!(
        "[notify_zulip::handle_pr_approved] event {:?}",
        &event.action
    );
    // direct approve
    // 2026-10-27T16:46:28.286201Z  INFO request{request_id="ddaee5a9-4d92-492d-b36c-6052b7ba0ce1"}: triagebot::handlers::notify_zulip: [notify_zulip::handle_pr_approved] handling event IssueCommentEvent { action: ReviewSubmitted, changes: None, issue: Issue { number: 136, body: "fix #127 ", created_at: 2026-01-20T15:36:19Z, updated_at: 2026-10-27T16:46:11Z, merged_at: None, merge_commit_sha: None, title: "Update README.md", html_url: "https://github.com/apiraino/test-triagebot/pull/136", user: GitHubUser { login: "apiraino", id: 6098822, type: User }, labels: [Label { name: "duplicate" }], assignees: [GitHubUser { login: "apiraino", id: 6098822, type: User }], pull_request: Some(PullRequestDetails { compare: OnceCell { value: None } }), draft: false, comments: None, review_comments: None, comments_url: "https://api.github.com/repos/apiraino/test-triagebot/issues/136/comments", repository: OnceLock(IssueRepository { organization: "apiraino", repository: "test-triagebot" }), base: Some(CommitBase { sha: "ec5a60cb5a560d6ad5ccd3c60903d391497ceaa3", git_ref: "master", repo: Some(Repository { full_name: "apiraino/test-triagebot", default_branch: "master", fork: false, parent: None }) }), head: Some(CommitBase { sha: "17c3617a60f53fde710f3d3ba194c4e5f58e6e30", git_ref: "apiraino-patch-7", repo: Some(Repository { full_name: "apiraino/test-triagebot", default_branch: "master", fork: false, parent: None }) }), state: Open, state_reason: None, milestone: None, mergeable: None, mergeable_state: None, author_association: AuthorAssociation(Owner) }, comment: Comment { id: 5670961356, node_id: "PRR_kwDOHB_D3s8AAAABUgQAzA", in_reply_to_id: None, pull_request_review_id: None, body: "", html_url: "https://github.com/apiraino/test-triagebot/pull/136#pullrequestreview-5670961356", user: GitHubUser { login: "jman-schief", id: 82455740, type: User }, created_at: Some(2026-10-27T16:46:25Z), updated_at: Some(2026-10-27T16:46:25Z), pr_review_state: Some(Approved), author_association: AuthorAssociation(Collaborator) }, repository: Repository { full_name: "apiraino/test-triagebot", default_branch: "master", fork: false, parent: None } }

    // review with comment (LGTM)
    // 2026-10-27T15:54:48.207172Z  INFO request{request_id="ca0579a8-84ee-4414-bc38-2c1029ebac45"}: triagebot::handlers::notify_zulip: [notify_zulip::handle_pr_approved] handling event IssueCommentEvent { action: Created, changes: None, issue: Issue { number: 136, body: "fix #127 ", created_at: 2026-01-20T15:36:19Z, updated_at: 2026-10-27T15:54:24Z, merged_at: None, merge_commit_sha: None, title: "Update README.md", html_url: "https://github.com/apiraino/test-triagebot/pull/136", user: GitHubUser { login: "apiraino", id: 6098822, type: User }, labels: [Label { name: "duplicate" }], assignees: [GitHubUser { login: "apiraino", id: 6098822, type: User }], pull_request: Some(PullRequestDetails { compare: OnceCell { value: None } }), draft: false, comments: None, review_comments: None, comments_url: "https://api.github.com/repos/apiraino/test-triagebot/issues/136/comments", repository: OnceLock(IssueRepository { organization: "apiraino", repository: "test-triagebot" }), base: Some(CommitBase { sha: "ec5a60cb5a560d6ad5ccd3c60903d391497ceaa3", git_ref: "master", repo: Some(Repository { full_name: "apiraino/test-triagebot", default_branch: "master", fork: false, parent: None }) }), head: Some(CommitBase { sha: "17c3617a60f53fde710f3d3ba194c4e5f58e6e30", git_ref: "apiraino-patch-7", repo: Some(Repository { full_name: "apiraino/test-triagebot", default_branch: "master", fork: false, parent: None }) }), state: Open, state_reason: None, milestone: None, mergeable: None, mergeable_state: None, author_association: AuthorAssociation(Owner) }, comment: Comment { id: 5670185191, node_id: "PRR_kwDOHB_D3s8AAAABUfgo5w", in_reply_to_id: None, pull_request_review_id: None, body: "LGTM", html_url: "https://github.com/apiraino/test-triagebot/pull/136#pullrequestreview-5670185191", user: GitHubUser { login: "jman-schief", id: 82455740, type: User }, created_at: Some(2026-10-27T15:54:46Z), updated_at: Some(2026-10-27T15:54:46Z), pr_review_state: Some(Approved), author_association: AuthorAssociation(Collaborator) }, repository: Repository { full_name: "apiraino/test-triagebot", default_branch: "master", fork: false, parent: None } }
    log::info!(
        "[notify_zulip::handle_pr_approved] handling event {:?}",
        event
    );

    // Zulip message configuration (from triagebot.toml: `[notify-zulip."beta-nominated".compiler]`)
    let mut z_labels_cfg = std::collections::HashMap::new();
    let notif_zulip_label_cfg = NotifyZulipLabelConfig {
        zulip_stream: 554919, // 474880, // #t-compiler/backports
        topic: "#{number}: beta-nominated".to_string(),
        messages_on_add: vec![
            "PR #{number} \"{title}\" fixes a regression and has been nominated for backport.
{recipients}, what do you think about it?
This topic will help T-compiler getting context about it.

Tip: to approve or decline from this Zulip thread, use:
@_**triagebot** backport approve
@_**triagebot** backport decline
"
            .to_string(),
            "/poll Should #{number} be beta backported?
approve
decline
don't know
"
            .to_string(),
        ],
        messages_on_remove: vec!["PR #{number}'s beta-nomination has been removed.".to_string()],
        github_comment: None,
        messages_on_close: vec![],
        messages_on_reopen: vec![],
        messages_on_close_success: vec![],
        required_labels: vec!["T-compiler".to_string()],
    };
    z_labels_cfg.insert("T-compiler".to_string(), notif_zulip_label_cfg);

    let mut z_labels = std::collections::HashMap::new();
    let notif_zulip_tables_cfg = NotifyZulipTablesConfig {
        subtables: z_labels_cfg,
    };
    z_labels.insert("T-compiler".to_string(), notif_zulip_tables_cfg);
    let _z_config = NotifyZulipConfig { labels: z_labels };

    // Only these are used:
    // event.issue.number
    // event.issue.title
    // event.issue.assignees
    // event.issue.user
    // event.issue.labels
    let z_issue = Issue {
        number: event.issue.number,
        body: "UNUSED".to_string(),
        created_at: event.issue.created_at,
        updated_at: event.issue.updated_at,
        merged_at: None,
        merge_commit_sha: None,
        title: event.issue.title.clone(),
        html_url: "UNUSED".to_string(),
        user: crate::github::repos::GitHubUser {
            id: event.issue.user.id,
            login: event.issue.user.login.clone(),
            r#type: crate::github::repos::GitHubUserType::Bot,
        }, // UNUSED
        labels: vec![], // UNUSED
        assignees: event.issue.assignees.clone(),
        state: crate::github::issue::IssueState::Open, // UNUSED
        state_reason: Some(octocrab::models::issues::IssueStateReason::Completed), // UNUSED
        milestone: None,
        comments_url: "UNUSED".to_string(),
        comments: None,
        repository: std::sync::OnceLock::new(), // UNUSED
        pull_request: None,
        draft: false,
        // approved: Some(true),
        review_comments: None,
        base: None,
        head: None,
        mergeable: None,
        mergeable_state: None,
        author_association: octocrab::models::AuthorAssociation::None.into(),
    };

    let z_event = IssuesEvent {
        action: IssuesAction::ReviewSubmitted,
        after: None,
        before: None,
        changes: None,
        issue: z_issue,
        // UNUSED
        repository: event.repository.clone(),
        // UNUSED
        sender: crate::github::repos::GitHubUser {
            id: 42,
            login: "UNUSED".to_string(),
            r#type: crate::github::repos::GitHubUserType::Bot,
        },
    };

    // Mimic what parse_input() returns
    let inputs = vec![NotifyZulipInput {
        // XXX: any NotificationType probably works
        notification_type: NotificationType::Labeled,
        label: Label {
            name: "T-compiler".to_string(),
        },
        include_config_names: vec!["T-compiler".to_string()],
    }];

    // 2026-10-27T16:46:28.286344Z DEBUG request{request_id="ddaee5a9-4d92-492d-b36c-6052b7ba0ce1"}: triagebot::handlers::notify_zulip: [notify_zulip::handle_pr_approved] inputs=[NotifyZulipInput { notification_type: Labeled, label: Label { name: "T-compiler" }, include_config_names: ["T-compiler"] }]
    log::debug!("[notify_zulip::handle_pr_approved] inputs={:?}", &inputs);

    handle_input(ctx, &config.notify_zulip.clone().unwrap(), &z_event, inputs).await
}

async fn get_zulip_ids(ctx: &Context, recipients: &[GitHubUser]) -> String {
    let gh_ids_fut = recipients
        .iter()
        .map(|recipient| async move { ctx.team.github_to_zulip_id(recipient.id).await });
    let zulip_ids = join_all(gh_ids_fut).await;

    let zulip_ids = zulip_ids
        .iter()
        .filter_map(|x| {
            if let Ok(id2) = x.as_ref()
                && let Some(id) = *id2
            {
                Some(format_zulip_mention(Mention::User(id), PingMode::Ping))
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    if !zulip_ids.is_empty() {
        zulip_ids.join(", ")
    } else {
        "".to_string()
    }
}

/// Replace the placeholder "{team}" with the correct team name
fn replace_team_to_be_nominated(labels: &[Label], msg: String) -> String {
    let teams = labels
        .iter()
        .map(|label| &label.name)
        .filter_map(|label| label.strip_prefix("T-"))
        .collect::<Vec<&str>>();

    // - If a single team label is found, replace the placeholder with that one
    // - If multiple team labels are found and one of them is "compiler", pick that one
    //   (currently the only team handling these Zulip notification)
    // - else, do nothing
    if let [team] = &*teams {
        msg.replace("{team}", team)
    } else if teams.contains(&"compiler") {
        msg.replace("{team}", "compiler")
    } else {
        msg
    }
}

#[test]
fn close_messages_uses_success_when_set() {
    use crate::config::NotifyZulipLabelConfig;

    let mut config = NotifyZulipLabelConfig {
        zulip_stream: 0,
        topic: "".to_string(),
        github_comment: None,
        messages_on_add: vec![],
        messages_on_remove: vec![],
        messages_on_close: vec!["generic".to_string()],
        messages_on_close_success: vec!["success".to_string()],
        messages_on_reopen: vec![],
        required_labels: vec![],
    };

    assert_eq!(
        close_messages(&config, CloseKind::Success),
        ["success".to_string()]
    );
    assert_eq!(
        close_messages(&config, CloseKind::Other),
        ["generic".to_string()]
    );

    // With no success message, a successful close uses the generic list too.
    config.messages_on_close_success = vec![];
    assert_eq!(
        close_messages(&config, CloseKind::Success),
        ["generic".to_string()]
    );

    // With only a success message, other closes produce no message.
    config.messages_on_close = vec![];
    config.messages_on_close_success = vec!["success".to_string()];
    assert_eq!(
        close_messages(&config, CloseKind::Success),
        ["success".to_string()]
    );
    assert!(close_messages(&config, CloseKind::Other).is_empty());
}

#[test]
fn close_only_success_skips_other_closes() {
    use crate::config::Config;
    use crate::github::{Issue, IssueState};
    use crate::tests::github;
    use chrono::Utc;

    let config = toml::from_str::<Config>(
        r#"
        [notify-zulip."I-high"]
        zulip_stream = 0
        topic = "topic"
        message_on_close_success = "done"
        "#,
    )
    .unwrap()
    .notify_zulip
    .unwrap();

    let event = |issue: Issue| IssuesEvent {
        action: IssuesAction::Closed,
        issue,
        changes: None,
        before: None,
        after: None,
        repository: Default::default(),
        sender: github::default_test_user(),
    };
    let notifies = |issue: Issue| !parse_close_reopen_input(&event(issue), &config).is_empty();

    let mut completed = github::issue()
        .state(IssueState::Closed)
        .labels(vec!["I-high"])
        .call();
    completed.state_reason = Some(IssueStateReason::Completed);
    let mut not_planned = github::issue()
        .state(IssueState::Closed)
        .labels(vec!["I-high"])
        .call();
    not_planned.state_reason = Some(IssueStateReason::NotPlanned);
    let mut merged = github::issue()
        .state(IssueState::Closed)
        .pr(true)
        .labels(vec!["I-high"])
        .call();
    merged.merged_at = Some(Utc::now());
    let unmerged = github::issue()
        .state(IssueState::Closed)
        .pr(true)
        .labels(vec!["I-high"])
        .call();

    assert!(notifies(completed));
    assert!(!notifies(not_planned));
    assert!(notifies(merged));
    assert!(!notifies(unmerged));
}

#[test]
fn close_kind_is_success_or_other() {
    use crate::tests::github::issue;
    use chrono::Utc;

    let mut pr = issue().pr(true).call();
    assert_eq!(close_kind(&pr), CloseKind::Other);
    pr.merged_at = Some(Utc::now());
    assert_eq!(close_kind(&pr), CloseKind::Success);

    let mut i = issue().pr(false).call();
    assert_eq!(close_kind(&i), CloseKind::Other); // no reason sent
    i.state_reason = Some(IssueStateReason::Completed);
    assert_eq!(close_kind(&i), CloseKind::Success);
    i.state_reason = Some(IssueStateReason::NotPlanned);
    assert_eq!(close_kind(&i), CloseKind::Other);
}

#[test]
fn test_notification() {
    let mut msg = replace_team_to_be_nominated(&[], "Needs `I-{team}-nominated`?".to_string());
    assert!(msg.contains("Needs `I-{team}-nominated`?"), "{msg}");

    msg = replace_team_to_be_nominated(
        &[Label {
            name: "T-cooks".to_string(),
        }],
        "Needs `I-{team}-nominated`?".to_string(),
    );
    assert!(msg.contains("I-cooks-nominated"), "{msg}");

    msg = replace_team_to_be_nominated(
        &[
            Label {
                name: "T-compiler".to_string(),
            },
            Label {
                name: "T-libs".to_string(),
            },
            Label {
                name: "T-cooks".to_string(),
            },
        ],
        "Needs `I-{team}-nominated`?".to_string(),
    );
    assert!(msg.contains("I-compiler-nominated"), "{msg}");

    msg = replace_team_to_be_nominated(
        &[
            Label {
                name: "T-libs".to_string(),
            },
            Label {
                name: "T-cooks".to_string(),
            },
        ],
        "Needs `I-{team}-nominated`?".to_string(),
    );
    assert!(msg.contains("Needs `I-{team}-nominated`?"), "{msg}");
}
