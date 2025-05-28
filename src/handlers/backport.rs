use std::sync::LazyLock;

use crate::config::BackportConfig;
use crate::github::{IssuesAction, IssuesEvent, Label};
use crate::handlers::Context;
use regex::Regex;
use tracing as log;

// Example triagebot.toml configuration
// ```
// [[backport.team1]]
// team_labels = ["T-compiler"]
// needs_labels = ["regression-from-stable-to-beta"]
// add_labels = ["beta-nominated"]

// [[backport.team2]]
// team_labels = ["T-libs", "T-libs-api"]
// trigger_labels = ["regression-from-stable-to-stable"]
// add_labels = ["beta-nominated","stable-nominated"]
// ```

// see https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue
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
    let config = match config {
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

    // Check PR for prerequisite team label
    let pr_labels: Vec<String> = event.issue.labels.iter().map(|l| l.name.clone()).collect();
    if contains_all(&pr_labels, &config.team_labels) {
        log::debug!("Skipping backport nomination: missing required team label");
        return Ok(None);
    }

    // Check marker text in the opening comment of the PR to retrieve the issue(s) being fixed
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
    // Retrieve issues being fixed by the PR
    // TODO: use `get_issues` and make a single HTTP query
    let mut issues = input
        .ids
        .iter()
        .copied()
        .map(|id| async move { event.repository.get_issue(&ctx.github, id).await });

    // Required labels the issue should have
    let needs_labels: Vec<String> = config
        .needs_labels
        .iter()
        .clone()
        .map(|l| l.clone())
        .collect();

    // XXX: these could be const
    let backport_labels: Vec<String> = vec![
        "beta-nominated".to_string(),
        "beta-accepted".to_string(),
        "stable-nominated".to_string(),
        "stable-accepted".to_string(),
    ];
    // auto-nominate for backport only patches fixing high/critical regressions
    let priority_labels = vec!["P-high".to_string(), "P-critical".to_string()];

    // Retrieve the issue(s) this pull request closes
    // Add backport nomination label to the pull request
    while let Some(issue) = issues.next() {
        let issue = issue.await.unwrap();
        let issue_labels: Vec<String> = issue
            .labels
            .iter()
            .clone()
            .map(|l| l.name.clone())
            .collect();
        // Skip this issue if it has already a backport label
        if contains_any(&issue_labels, &backport_labels) {
            log::debug!("Issue #{} already has a backport label", issue.number);
            return Ok(());
        }

        // Check for prerequisite priority label
        if contains_any(&issue_labels, &priority_labels) {
            log::debug!(
                "Skipping backport nomination: issue #{} does not have required priority label ({:?})",
                issue.number,
                priority_labels
            );
            return Ok(());
        }

        // Check if issue has the required labels (most importantly the one identifying it as a regression)
        // Add backport nomination label(s) to issue
        if contains_all(&issue_labels, &needs_labels) {
            let mut new_labels = issue.labels().to_owned();
            new_labels.extend(config.add_labels.iter().cloned().map(|name| Label { name }));
            return issue.add_labels(&ctx.github, new_labels).await;
        } else {
            log::debug!(
                "Skipping backport nomination: Issue #{} is missing required labels ({:?})",
                issue.number,
                needs_labels
            );
        }
    }

    Ok(())
}

fn contains_any(haystack: &Vec<String>, needles: &Vec<String>) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn contains_all(haystack: &Vec<String>, needles: &Vec<String>) -> bool {
    needles.iter().all(|needle| haystack.contains(needle))
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
