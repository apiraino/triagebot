# How is the triagebot codebase organized

GOAL: try explaining a bit more in the README:
- The Zulip integration (f.e. StreamCommand and ChatCommand, why are they different)
- probably other stuff that I learned "by doing" or by copy and paste but without really understanding the high-level architecture
- The binaries (prioritization-agenda & Co.): `Step`, `Query`, `QueryMap`

Discussed in https://rust-lang.zulipchat.com/#narrow/dm/250987,266526-dm/near/601755152

## What is a handler and how is it structured

TODO: explain the macros
- `issue_handlers!()` https://github.com/rust-lang/triagebot/blob/master/src/handlers.rs#L360
- `command_handlers!()`: https://github.com/rust-lang/triagebot/blob/master/src/handlers.rs#L509

and the events they handle. Show a minimal example of handler and what functions should contain

## To which event can be handlers attached to

TODO: To which GH webhook event they map?

See `IssuesAction`: https://github.com/rust-lang/triagebot/blob/master/src/github/webhook/event.rs#L208

Issues and pull requests events: https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request

## Handlers and Commands

Explain the difference between `handlers` and `commands`.

## How to add a new handler that reacts to a GitHub event (webhook)

Create a new module under `./src/handlers/` and will be handled by the macro `issue_handlers!()`

## Add a new Handler

To add a new `handler`, add code in the following points:
- Create a module under `src/handlers/` (implementing needed methods, please also document at the top of the file what the handler is for)
- Add it to the handlers macro `issue_handlers!()` in `src/handlers.rs`

## Add a new Command

To add a new `Command`, add code in the following points:
- In `parser/src/command.rs` a new entry in the `enum Command`
- Add it to the `impl Command` as well
- Add it to the Command macro `command_handlers!()` in `src/handlers.rs`

## How to add a new command that reacts to a Zulip event (webhook)

Add a new struct for the new command in one (or both) these structs in `./src/zulip/commands.rs`:
- `ChatCommand` for commands sent to the Zulip bot `@triagebot` in a DM
- `StreamCommand` for commands sent to the Zulip bot `@triagebot` in any Zulip stream

if you want the same command to be available both in DMs and streams, you need to add it to both structs.

Run `cargo check`, the compiler error will drive you where to add additional code.

If you want to allow/disallow the impersonation mode (see docs https://forge.rust-lang.org/triagebot/zulip-commands.html#impersonation), add you command here
https://github.com/rust-lang/triagebot/blob/master/src/zulip.rs#L1214

The webhook commands and the `Message` payload are parsed in `./src/zulip.rs`.

## Database use

Database connection pool are handled in `./src/db.rs`. We don't have a real migrations management. Migrations must be appended in that file(pay attention to the formatting).

Database CRUD code should reside under `./src/db/`. To keep the code better organized, split code in different modules.
