use std::collections::HashMap;
use std::sync::LazyLock;

use crate::config::BackportTeamConfig;
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

// TODO: handle somewhere else also these cases:
// PR is opened without T-label (can it happen or is it automatically applied?)
// - User adds a T-label
// - this handler should trigger as well
// or
// the regression is labeled with a P-label at a second time
// - this handler should trigger as well

// see https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue
static CLOSES_ISSUE_REGEXP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(?i)(close[sd]*|fix([e]*[sd]*)?|resolve[sd]*) #(\\d+)").unwrap());

#[derive(Default, Debug)]
pub(crate) struct BackportInput {
    /// Issues fixed by this PR
    ids: Vec<u64>,
    /// Labels profile
    // (Labels expected to be found in these issues -> Labels that will be added to the PR fixing the issues)
    profile_labels: HashMap<String, Vec<String>>,
}

pub(super) async fn parse_input(
    _ctx: &Context,
    event: &IssuesEvent,
    config: Option<&BackportTeamConfig>,
) -> Result<Option<BackportInput>, String> {
    let config = match config {
        Some(config) => config,
        None => return Ok(None),
    };

    if !matches!(event.action, IssuesAction::Opened) && !event.issue.is_pr() {
        log::info!(
            "Skipping backport event because: IssuesAction = {:?} issue.is_pr() {}",
            event.action,
            event.issue.is_pr()
        );
        return Ok(None);
    }
    let pr = &event.issue;

    // TODO: make this a const
    let backport_labels: Vec<String> = vec![
        "beta-nominated".to_string(),
        "beta-accepted".to_string(),
        "stable-nominated".to_string(),
        "stable-accepted".to_string(),
    ];

    let pr_labels: Vec<String> = pr.labels.iter().map(|l| l.name.clone()).collect();
    if contains_any(&pr_labels, &backport_labels) {
        log::debug!("PR #{} already has a backport label", pr.number);
        return Ok(None);
    }

    // Retrieve backport config for this PR, based on its team label(s)
    // If the PR has no team label matching any [backport.*.team_labels] config, the backport labelling will be skipped
    let mut input = BackportInput::default();
    let valid_configs: Vec<_> = config
        .configs
        .iter()
        .clone()
        .filter(|(cfg_name, cfg)| {
            log::debug!("backport.{} has team_labels {:?}", cfg_name, cfg.team_labels);
            if !contains_all(&pr_labels, &cfg.team_labels) {
                log::debug!(
                    "Skipping backport nomination: PR is missing one or more of the required team labels: {:?}",
                    pr_labels
                );
                return false;
            }
            log::debug!(
                "Applying backport.{} config={:?}",
                cfg_name,
                cfg.team_labels
            );
            let x = cfg.needs_labels.clone();
            input.profile_labels.insert(x[0].clone(), cfg.add_labels.clone());
            true
        })
        .collect();
    if valid_configs.is_empty() {
        // TODO: make this comment more succint
        log::warn!(
            "Skipping backport nomination: could not find a suitable backport config. Please ensure the triagebot.toml has a [backport] section where `team_labels` matching the team label(s) for PR #{}.",
            pr.number
        );
        return Ok(None);
    }

    // Check marker text in the opening comment of the PR to retrieve the issue(s) being fixed
    for caps in CLOSES_ISSUE_REGEXP.captures_iter(&event.issue.body) {
        let id = caps.get(3).unwrap().as_str();
        let id = match id.parse::<u64>() {
            Ok(id) => id,
            Err(err) => {
                return Err(format!("Failed to parse issue id `{}`, error: {}", id, err));
            }
        };
        input.ids.push(id);
    }
    log::info!(
        "Will handle event action {:?} in backport. Regression IDs found {:?}",
        event.action,
        input.ids
    );

    return Ok(Some(input));
}

pub(super) async fn handle_input(
    ctx: &Context,
    _config: &BackportTeamConfig,
    event: &IssuesEvent,
    input: BackportInput,
) -> anyhow::Result<()> {
    let pr = &event.issue;
    log::info!("PR#{} Handling with input {:?}", pr.number, input);

    // Retrieve the issue(s) this pull request closes
    // TODO: use `Repositories::get_issues` and make a single HTTP query
    let mut issues = input
        .ids
        .iter()
        .copied()
        .map(|id| async move { event.repository.get_issue(&ctx.github, id).await });

    // auto-nominate for backport only patches fixing high/critical regressions
    // For `P_{medium,low}` regressions, let the author decide
    let priority_labels = vec!["P-high".to_string(), "P-critical".to_string()];

    // Add backport nomination label to the pull request
    while let Some(issue) = issues.next() {
        let issue = issue.await.unwrap();
        log::debug!("Input parsing issue: {:?}", issue);
        let mut regression_label = String::new();
        let issue_labels: Vec<String> = issue
            .labels
            .iter()
            .map(|l| {
                // save regression label for later
                if l.name.starts_with("regression-from-") {
                    regression_label = l.name.clone();
                }
                l.name.clone()
            })
            .collect();
        log::debug!("Issue labels: {:?}", issue_labels);

        // Check issue for a prerequisite regression label
        let regression_labels = vec![
            "regression-from-stable-to-nightly".to_string(),
            "regression-from-stable-to-beta".to_string(),
            "regression-from-stable-to-stable".to_string(),
        ];
        if regression_label.is_empty() {
            log::warn!(
                "Skipping backport nomination: issue #{} does not have prerequisite regression label ({:?})",
                issue.number,
                regression_labels
            );
            return Ok(());
        }

        // Check issue for a prerequisite priority label
        if !contains_any(&issue_labels, &priority_labels) {
            log::warn!(
                "Skipping backport nomination: issue #{} does not have prerequisite priority label ({:?})",
                issue.number,
                priority_labels
            );
            return Ok(());
        }

        // figure out the labels to be added according to the regression label
        let add_labels = input.profile_labels.get(&regression_label);
        if add_labels.is_none() {
            log::warn!(
                "Skipping backport nomination: nothing to do for issue #{}. No config found for regression label ({:?})",
                issue.number,
                regression_labels
            );
            return Ok(());
        }

        // Add backport nomination label(s) to PR
        let mut new_labels = pr.labels().to_owned();
        new_labels.extend(
            add_labels
                .unwrap()
                .iter()
                .cloned()
                .map(|name| Label { name }),
        );
        log::debug!(
            "PR#{} adding labels for backport {:?}",
            pr.number,
            new_labels
        );
        return pr.add_labels(&ctx.github, new_labels).await;
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
    use crate::handlers::backport::CLOSES_ISSUE_REGEXP;

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
            for caps in CLOSES_ISSUE_REGEXP.captures_iter(test_str) {
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
