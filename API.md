Endpoints are defined here `triagebot/src/main.rs`

- GET|POST /
    returns 200 OK and message "Triagebot is awaiting triage."

- GET /triage
    returns the triage dashboards

- GET /triage/:owner/:repo", "pulls".to_string());
    - GET triage/apiraino/rust-lang

- GET /bors-commit-list, returns this query
  ```
    select sha, parent_sha, time, pr
    from rustc_commits
    where time >= current_date - interval '168 days'
    order by time desc;",
  ```

- GET /notifications?user=<gh_username>, returns list of notifications for a github user

- POST /zulip-hook, send a Zulip command to the triagebot

- POST /github-hook, with "X-GitHub-Event" and "X-Hub-Signature" headers

### Setup

I have a repository under https://github.com/apiraino/test-triagebot/

I want to send a message to *my* rustbot with `@rustbot label +SomeLabel`

I need a `triagebot.toml` file in my repository. This file will allow the `@rustbot` commands to reach the only triagebot available in the world, listening on `https://triage.rust-lang.org/`.

Let's say I want my own triagebot running on a server. I need to start setting these env variables:
- `GITHUB_API_TOKEN`
- `GITHUB_WEBHOOK_SECRET`

The `GITHUB_WEBHOOK_SECRET` will be used to calculate a SHA1 on every payload the triagebot receives.

### Triagebot test environment

The following parts are needed:

- A github repository. The repo must be public (else the retrieval of the file `triagebot.toml` will fail).
  - Configure the github repository with a webhook with the location of the triagebot (ex. `https://triagebot.your-domain.org/github-hook`) and a `secret`. That secret is also set in the env var `GITHUB_WEBHOOK_SECRET` when running the triagebot. The secret is used to create a SHA1 signature to every payload the triagebot receives. The validation of this signature [happens here](https://github.com/rust-lang/triagebot/blob/73d76061033fca22f8c032d0a39ea885120512cc/src/payload.rs#L15-L39). See [Github docs](https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks) to configure this webhook.
  - The github repository has a `triagebot.toml` file with the allowed actions.
  
- A triagebot deployed on a publicly reachable address, e.g. `https://triagebot.mydomain.org`.
  - A Postgres DB (DB migrations will run when the triagebot is started).
    ```
    CREATE ROLE triagebot login password 'HAHAHA';
    CREATE DATABASE triagebot with ENCODING 'UTF8' template=template1 owner=triagebot;
    ```
  - The triagebot should run with these env variables:
    - `DATABASE_URL`: the endpoint to reach the Postgres DB (f.e. `DATABASE_URL="postgres://user:pwd@127.0.0.1:5432/dbname"`)
    - `GITHUB_API_TOKEN`: a github personal token (created from `https://github.com/settings/tokens`)
    - `GITHUB_WEBHOOK_SECRET`: a shared secret between the webhook and the triagebot

When adding a comment to an issue / pull request in the github repository, a mention to the `@rustbot` (or `@TriageBot`) github user is needed. These names are checked against the file `https://team-api.infra.rust-lang.org//v1/teams.json`. When a command with a mention to the `@rustbot` is added the github webhook will send a `POST /github-hook` to the triagebot. If the payload is validated, the triagebot will emit a series of API calls to github.
