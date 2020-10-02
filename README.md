# Triagebot

This is the triage and team assistance bot for the rust-lang organization.

For the Rust project the triagebot is deployed on `https://triagebot.infra.rust-lang.org/`.

Please see the [wiki] or [Rust Forge] for the triagebot documentation and available commands, feel free to contribute edits if you find something helpful!

[wiki]: https://github.com/rust-lang/triagebot/wiki
[Rust Forge]: https://forge.rust-lang.org/platforms/zulip/triagebot.html

## Installation

To compile the Triagebot you need OpenSSL development library to be installed (e.g. for Ubuntu-like Linux distributions `sudo apt install libssl-dev`).

Run `cargo build` to compile the triagebot.

The `GITHUB_WEBHOOK_SECRET`, `GITHUB_API_TOKEN` and `DATABASE_URL` environment
variables need to be set.

If `GITHUB_API_TOKEN` is not set, the token can also be stored in `~/.gitconfig` in the
`github.oauth-token` setting.

To configure the GitHub webhook, point it to the `/github-hook` path of your
webserver (by default `http://localhost:8000`), configure the secret you chose
in `.env`, set the content type to `application/json` and select all events.

## Contributors

Thanks for contributing a patch! Please have a look at the [developer](./developer-setup.md) documentation for more details on how the triagebot work and how to setup a local testing environment.

## License

Triagebot is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
