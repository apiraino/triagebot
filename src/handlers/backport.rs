use std::sync::LazyLock;

use crate::config::BackportConfig;
use crate::github::{IssuesAction, IssuesEvent, Label};
use crate::handlers::Context;
use regex::Regex;
use tracing as log;

// Example triagebot configuration
// ```
// [backport]
// trigger_labels = ["regression-from-stable-to-beta"]
// labels_to_add = ["beta-nominated"]
// ```

// See https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue
static CLOSES_ISSUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(?i)(close[sd]*|fix([e]*[sd]*)?|resolve[sd]*) #(\\d+)").unwrap());

pub(crate) struct BackportInput {
    ids: Vec<u64>,
}

pub(super) async fn parse_input(
    _ctx: &Context,
    event: &IssuesEvent,
    config: Option<&BackportConfig>,
) -> Result<Option<BackportInput>, String> {
    let _config = match config {
        Some(config) => config,
        None => return Ok(None),
    };

    // XXX: commented the action for testing
    // if !matches!(event.action, IssuesAction::Opened)
    if !event.issue.is_pr() {
        log::info!(
            "Skipping backport event because: IssuesAction = {:?} issue.is_pr() {}",
            event.action,
            event.issue.is_pr()
        );
        return Ok(None);
    }

    let mut ids = vec![];
    for caps in CLOSES_ISSUE.captures_iter(&event.issue.body) {
        let id = caps.get(3).unwrap().as_str();
        let id = match id.parse::<u64>() {
            Ok(id) => id,
            Err(err) => {
                return Err(format!("Failed to parse issue id `{}`, error: {}", id, err));
            }
        };
        ids.push(id);
    }
    log::info!(
        "Handling event action {:?} in backport. Regression IDs found {:?}",
        event.action,
        ids
    );

    return Ok(Some(BackportInput { ids }));
}

pub(super) async fn handle_input(
    ctx: &Context,
    config: &BackportConfig,
    event: &IssuesEvent,
    input: BackportInput,
) -> anyhow::Result<()> {
    let mut issues = input
        .ids
        .iter()
        .copied()
        .map(|id| async move { event.repository.get_issue(&ctx.github, id).await });

    // Labels that will trigger a backport nomination
    let trigger_labels: Vec<_> = config
        .trigger_labels
        .iter()
        .cloned()
        .map(|name| Label { name })
        .collect();

    // Add backport nomination label to this pull request
    while let Some(issue) = issues.next() {
        let issue = issue.await.unwrap();
        if issue
            .labels
            .iter()
            .any(|issue_label| trigger_labels.contains(issue_label))
        {
            let mut new_labels = event.issue.labels().to_owned();
            new_labels.extend(
                config
                    .labels_to_add
                    .iter()
                    .cloned()
                    .map(|name| Label { name }),
            );
            return event.issue.add_labels(&ctx.github, new_labels).await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::handlers::backport::CLOSES_ISSUE;

    #[tokio::test]
    async fn backport_match_comment() {
        let mut ids: Vec<u64> = vec![];
        let test_strings = vec![
            ("close #10", vec![10]),
            ("closes #10", vec![10]),
            ("closed #10", vec![10]),
            ("fix #10", vec![10]),
            ("fixes #10", vec![10]),
            ("fixed #10", vec![10]),
            ("resolve #10", vec![10]),
            ("resolves #10", vec![10]),
            ("resolved #10", vec![10]),
            (
                "Fixes #20, Resolves #21, closed #22, LOL #23",
                vec![20, 21, 22],
            ),
            ("Resolved #10", vec![10]),
            ("Fixes #10", vec![10]),
            ("Closes #10", vec![10]),
        ];
        for test_case in test_strings {
            let test_str = test_case.0;
            let expected = test_case.1;
            for caps in CLOSES_ISSUE.captures_iter(test_str) {
                // println!("caps {:?}", caps);
                let id = caps.get(3).unwrap().as_str();
                ids.push(id.parse::<u64>().unwrap());
            }
            // println!("ids={:?}", ids);
            assert_eq!(ids, expected);
            ids = vec![];
        }
    }
}
