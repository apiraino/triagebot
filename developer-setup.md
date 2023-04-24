## Brief architecture overview

The triagebot is used to do many tasks and sits in the middle of a number of components. A very high-level view could be summarized in:

- A github repository (currently only the `rust-lang` organization is supported): receiving commands for issues (such as labeling, assignment, user mentions, etc.)
- A Zulip chat instance: sending commands and receiving notifications
- The triagebot: a web service with access to a database. It sits in between of all these components and act as a relay forwarding commands both ways.

Other components on the infra cannot be easily deployed locally.

## Test environment

In order to test commands from Zulip to the triagebot, you need three components:

- A Zulip chat instance deployed on your local host (or [hosted for free](https://zulip.com/plans))
- The triagebot listening on your local host
- A Github repository to verify the commands sent by the Zulip chat

For commands interacting with a Github repository, you can prepare a test github repository under your account and create a dedicated test [access token](https://github.com/settings/tokens/new) to send commands to it.

### Requirements

- [Docker](https://docs.docker.com/engine/install/) and [Docker compose](https://docs.docker.com/compose/install/) installed on your workstation

- About 3gb disk space and a fast internet connection

- A valid API token in your Github account ([here's how to create one](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)) with a single permission: `public_repo`.

- Ensure your workstation resolves `zulip.local` locally. Example, add this to your `/etc/hosts`:
  ```
  # URL to the Zulip instance
  127.0.0.1   zulip.local
  # URL to our Zulip organization
  127.0.0.1   testorg.zulip.local
  ```

- Get the Docker compose file and configure Docker Compose for a full Zulip installation:
  ```
  git clone --depth=1 https://github.com/zulip/docker-zulip.git
  cd docker-zulip
  ```

- Edit `docker-compose.yml` as follows, this will let you conveniently access the Zulip Postgres DB and use it also for the triagebot:
  ```
  --- a/docker-compose.yml
  +++ b/docker-compose.yml
  @@ -8,9 +8,11 @@ services:
         # Note that you need to do a manual `ALTER ROLE` query if you
         # change this on a system after booting the postgres container
         # the first time on a host.  Instructions are available in README.md.
  -      POSTGRES_PASSWORD: 'REPLACE_WITH_SECURE_POSTGRES_PASSWORD'
  +      POSTGRES_PASSWORD: 'zulip'
       volumes:
         - '/opt/docker/zulip/postgresql/data:/var/lib/postgresql/data:rw'
  +    ports:
  +      - '5432:5432'
     memcached:
       image: 'memcached:alpine'
       command:
  @@ -72,7 +74,7 @@ services:
         # These should match RABBITMQ_DEFAULT_PASS, POSTGRES_PASSWORD,
         # MEMCACHED_PASSWORD, and REDIS_PASSWORD above.
         SECRETS_rabbitmq_password: 'REPLACE_WITH_SECURE_RABBITMQ_PASSWORD'
  -      SECRETS_postgres_password: 'REPLACE_WITH_SECURE_POSTGRES_PASSWORD'
  +      SECRETS_postgres_password: 'zulip'
         SECRETS_memcached_password: 'REPLACE_WITH_SECURE_MEMCACHED_PASSWORD'
         SECRETS_redis_password: 'REPLACE_WITH_SECURE_REDIS_PASSWORD'
         SECRETS_secret_key: 'REPLACE_WITH_SECURE_SECRET_KEY'
  @@ -93,7 +98,7 @@ services:
         SECRETS_memcached_password: "REPLACE_WITH_SECURE_MEMCACHED_PASSWORD"
         SECRETS_redis_password: "REPLACE_WITH_SECURE_REDIS_PASSWORD"
         SECRETS_secret_key: "REPLACE_WITH_SECURE_SECRET_KEY"
  -      SETTING_EXTERNAL_HOST: "localhost.localdomain"
  +      SETTING_EXTERNAL_HOST: "zulip.local"
  ```

- Pull all the containers and start them up
  `docker-compose up -d`
  and to follow the logs:
  `docker-compose logs -f`

- Check if the instance is up, you should receive a 301 from Zulip chat:
  ```
  $ curl -i http://zulip.local
  HTTP/1.1 301 Moved Permanently
  ```

### Create your local Zulip organization

Let's create a `TestOrg` organization. 

- Run:
  `docker-compose exec -u zulip zulip /home/zulip/deployments/current/manage.py generate_realm_creation_link`

now open the link received with a web browser. Complete the wizard and the local Zulip instance should be available. It cannot send emails unless you configure so, but it should not be needed for testing the triagebot. From now on you should be able to login into the Zulip chat instance with the credentials you've just created.

Now attempt a first login. Open this URL to login: `https://testorg.zulip.local/accounts/login/`

If your browser cannot reach this URL, ensure you have it mapped in your `/etc/hosts` (see above).

### Hack your Zulip local instance 

Before being able to test interactions with your local triagebot from your own Zulip instance, a few manual hacks are needed.

Due to [this Zulip issue](https://github.com/zulip/zulip/issues/20490), messages originating from your dockerized local development Zulip instance and directed to the host or other private addresses will be blocked by the Zulip HTTP proxy ([Smokescreen](https://github.com/stripe/smokescreen)). This is the error you will see when you send a message: "b"Egress proxying is denied to host '....': The destination address (...) was denied by rule 'Deny: Private Range'. destination address was denied by rule, see error."

In order to work around this, you need to get inside the Zulip container and reconfigure Smokescreen. First etrieve the address of your Docker network interface with `ip addr show docker0`. This address is your workstation as seen from the Docker container. Example output:
  ```
  $ ip addr show docker0
  12: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:d9:d0:c4:61 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:d9ff:fed0:c461/64 scope link 
       valid_lft forever preferred_lft forever
  ```

Then edit the SmokeScreen config file and whitelist this address: 
```
$ docker-compose exec -u root zulip bash
# apt update && apt install -y nano
# nano /etc/supervisor/conf.d/zulip/smokescreen.conf
```
Append to the command the parameter `--allow-address 172.17.0.1`, save and restart the service with:
```
# supervisorctl update
# supervisorctl restart smokescreen
```

Open the file `./src/zulip.rs +51` and jump to the definition of `zulip_map()`, then of `BASE_URL`, in the crate `rust_team_data/src/v1.rs` and change the following:
```diff
@@ -1,7 +1,7 @@
 use indexmap::IndexMap;
 use serde::{Deserialize, Serialize};
 
-pub static BASE_URL: &str = "https://team-api.infra.rust-lang.org/v1";
+pub static BASE_URL: &str = "http://127.0.0.1:8001";
 
 #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
 #[serde(rename_all = "snake_case")]
```

Then activate a local http server in `./mocks` (for example: `python -m http.server 8001`) to reply to those requests.

### Create a bot hook on Zulip


- Go to "Settings" > "Your bots" > "Add a new bot", add the following sample data:
  - Type of the bot: `webkook outgoing`
  - Full name: `TestBot`
  - Bot email (can be anything, it's not needed): `test-bot@testorg.zulip.local`
  - Endpoint URL (must be the allowed address in SmokeScreen): `http://172.17.0.1:8000/zulip-hook`
  - Outgoing webhook message format: `Zulip`
  
- Download the "zuliprc" from the "Active bots" tab and save it somewhere, example file:
  ```
  [api]
  email=test-bot@testorg.zulip.local
  key=gddqQu1bbOn6nX90a0LPV1kOa9kdBLpE
  site=https://testorg.zulip.local
  token=OEuFkrQRhL2m4VKgHEczaKloa7Rw87av
  ```

### Create your test repository on Github

TODO

We need to mock these remote requests:
- https://team-api.infra.rust-lang.org/v1/zulip-map.json
- calls to the `rust-lang/rust` repository issues and PRs

In order to avoid spamming the Rust lang repository, let's create our own repo that will receive messages from our Zulip local instance relayed by our local triagebot. 

### Run the bot

Set these env variables, based on the previous settings:

```bash
# export DATABASE_URL="postgres://zulip:zulip@127.0.0.1:5434/zulip"
$ export ZULIP_TOKEN=OEuFkrQRhL2m4VKgHEczaKloa7Rw87av
$ export GITHUB_API_TOKEN=<YOUR_GITHUB_TOKEN>
```

Then fire up the bot (it will connect to the Dockerized DB): `RUST_LOG=debug cargo run --bin triagebot`

## Your first Zulip command

TODO

Now open on your Zulip instance a private message session with the bot you created earlier. Send it any message, you should see the bot reply with something like:
`Unknown Zulip user. Please add zulip-id = xxx to your file in rust-lang/team.`

Edit the file `mocks/zulip-map.json`, the format is:
```
{
  "users": {
    "ZULIP_USER_ID": GH_USER_ID
  }
}
```

replacing `ZULIP_USER_ID` with the Zulip user id of the test instance and `GH_USER_ID` with your real GitHub user.

Send again a message and the rustbot should reply with "Unknown command". Congratulations, you can talk from your Zulip instance to your local triagebot.

But this is only half of the job. The other half is having the oppsite working.

## What does a Zulip command look like

If you want to send a Zulip command to the triagebot programmatically, this is more or less the corresponding `cURL` call:

```bash
curl http://172.17.0.1:8000/zulip-hook \
     -H "Host: 172.17.0.1:8000" \
     -H "token: the-zulip-bot-token" \
     -H "Content-Type: application/json" \
     -d '{...payload...}'
```

The payload is a Zulip [Request](https://github.com/rust-lang/triagebot/blob/master/src/zulip.rs#L11-L33) and contains command and parameters.

Example payload:
```json
{
  "data": "the-triagebot-command",
  "token": "the-zulip-bot-token",
  "message": {
    "sender_id": 123456,
    "recipient_id": 123456,
    "sender_full_name": "Jon Asch",
    "type": "stream"
  }
}
```

`data` contains the command, Zulip commands for issues [are documented here](https://forge.rust-lang.org/platforms/zulip/triagebot.html#issue-notifications). `sender_id` and `recipient_id` 
`data` is the command you want to send. Available commands are listed on the Triagebot wiki](https://github.com/rust-lang/triagebot/wiki).
