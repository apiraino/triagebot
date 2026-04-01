use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::io::Error;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};

use crate::github::{self, GithubClient, Repository};
use crate::http_client::get_compiler_perf_triage_logs;
use crate::team_data::TeamClient;

#[async_trait]
pub trait Action {
    async fn call(&self) -> anyhow::Result<String>;
}

pub struct Step<'a> {
    pub name: &'a str,
    pub actions: Vec<Query<'a>>,
}

pub struct Query<'a> {
    /// Vec of (owner, name)
    pub repos: Vec<(&'a str, &'a str)>,
    pub queries: Vec<QueryMap<'a>>,
}

#[derive(Copy, Clone)]
pub enum QueryKind {
    List,
    Count,
    Skip,
}

pub struct QueryMap<'a> {
    pub name: &'a str,
    pub kind: QueryKind,
    pub query: Arc<dyn github::issue_query::IssuesQuery + Send + Sync>,
}

#[derive(Debug, serde::Serialize)]
pub struct IssueDecorator {
    pub number: u64,
    pub title: String,
    pub html_url: String,
    pub repo_name: String,
    pub labels: String,
    pub author: String,
    pub assignees: String,
    // Human (readable) timestamp
    pub updated_at_hts: String,

    pub fcp_details: Option<FCPDetails>,
    pub mcp_details: Option<MCPDetails>,
    pub is_blocked: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FCPConcernDetails {
    pub name: String,
    pub reviewer_login: String,
    pub concern_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FCPReviewerDetails {
    pub github_login: String,
    pub zulip_id: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FCPDetails {
    pub bot_tracking_comment_html_url: String,
    pub bot_tracking_comment_content: String,
    pub initiating_comment_html_url: String,
    pub initiating_comment_content: String,
    pub disposition: String,
    pub should_mention: bool,
    pub pending_reviewers: Vec<FCPReviewerDetails>,
    pub concerns: Vec<FCPConcernDetails>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MCPDetails {
    pub zulip_link: String,
    pub concerns: Option<Vec<(String, String)>>,
}

// pub static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| match Tera::new("templates/*") {
//     Ok(t) => t,
//     Err(e) => {
//         println!("Parsing error(s): {e}");
//         ::std::process::exit(1);
//     }
// });

pub static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| {
    match {
        // TODO: add all templates at compile-time, in the right order (!)
        let tpl_contents = include_str!("../templates/prioritization_agenda.tt");
        let mut tera = Tera::default();
        tera.add_raw_template("prioritization_agenda", &tpl_contents)
            .unwrap();
        Ok::<Tera, Error>(tera)
    } {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {e}");
            ::std::process::exit(1);
        }
    }
});

pub fn to_human(d: DateTime<Utc>) -> String {
    let d1 = chrono::Utc::now() - d;
    let days = d1.num_days();
    if days > 60 {
        format!("{} months ago", days / 30)
    } else {
        format!("about {days} days ago")
    }
}

#[async_trait]
impl Action for Step<'_> {
    async fn call(&self) -> anyhow::Result<String> {
        let mut gh = GithubClient::new_from_env();
        gh.set_retry_rate_limit(true);
        let team_api = TeamClient::new_from_env();
        let today = chrono::Utc::now().date_naive();

        // If compiling the T-compiler agenda, retrieve perf. triage logs for this week
        let triage_logs = if self.name == "prioritization_agenda" {
            match get_compiler_perf_triage_logs(&gh, today).await {
                Ok(logs) => logs,
                Err(err) => {
                    tracing::log::debug!("Compiler triage logs failed because: {:?}", err);
                    format!(
                        "TODO: failed to retrieve triage logs for this week ({today}), get them manually."
                    )
                }
            }
        } else {
            "".to_string()
        };

        let mut context = Context::new();
        let mut results = HashMap::new();

        let mut handles: Vec<tokio::task::JoinHandle<anyhow::Result<(String, QueryKind, Vec<_>)>>> =
            Vec::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(5));

        // TODO: test the whole shebangs
        let xxx = true;
        if xxx {
            for Query { repos, queries } in &self.actions {
                for repo in repos {
                    let repository = Repository {
                        full_name: format!("{}/{}", repo.0, repo.1),
                        // These are unused for query.
                        default_branch: "master".to_string(),
                        fork: false,
                        parent: None,
                    };

                    for QueryMap { name, kind, query } in queries {
                        let semaphore = semaphore.clone();
                        let name = String::from(*name);
                        let kind = *kind;
                        let repository = repository.clone();
                        let gh = gh.clone();
                        let team_api = team_api.clone();
                        let query = query.clone();
                        handles.push(tokio::task::spawn(async move {
                            let _permit = semaphore.acquire().await?;
                            let fcps_groups = ["proposed_fcp", "in_pre_fcp", "in_fcp"];
                            let mcps_groups = [
                                "mcp_new_not_seconded",
                                "mcp_old_not_seconded",
                                "mcp_accepted",
                                "in_pre_fcp",
                                "in_fcp",
                            ];
                            let issues = query
                                .query(
                                    &repository,
                                    fcps_groups.contains(&name.as_str()),
                                    mcps_groups.contains(&name.as_str())
                                        && repository.full_name.contains("rust-lang/compiler-team"),
                                    &gh,
                                    &team_api,
                                )
                                .await?;
                            Ok((name, kind, issues))
                        }));
                    }
                }
            }
        }

        if xxx {
            for handle in handles {
                let (name, kind, issues) = handle.await.unwrap()?;
                match kind {
                    QueryKind::List => {
                        results.entry(name).or_insert(Vec::new()).extend(issues);
                    }
                    QueryKind::Count => {
                        let count = issues.len();
                        let result = if let Some(value) = context.get(&name) {
                            value.as_u64().unwrap() + count as u64
                        } else {
                            count as u64
                        };

                        context.insert(name, &result);
                    }
                    QueryKind::Skip => {
                        // results.entry(name).or_insert(Vec::new()).extend(issues);
                        context.insert(name, "no-op");
                    }
                }
            }
        }

        for (name, issues) in &results {
            context.insert(name, issues);
        }
        context.insert("CURRENT_DATE", &today);
        context.insert("triage_logs", &triage_logs);

        dbg!(&TEMPLATES.get_template_names().collect::<Vec<&str>>());
        dbg!(&TEMPLATES);
        dbg!(&context);

        let r = TEMPLATES.render(self.name, &context).unwrap();

        dbg!(r);

        Ok("DONE".to_string())
    }
}
