## Brief architecture overview

The triagebot is used to do many tasks and sits in the middle of many components. A very high-level view could be summarized in:

- A git repository (currently only Github is supported): receiving commands for issues (such as labeling, assignment, user mentions, etc.)
- A Zulip chat instance: sending commands and receiving notifications
- The triagebot: a web service with access to a database. It sits in between of all these components and act as a relay forwarding commands both ways.

Other components on the infra cannot be easily deployed locally.

## Test environment

In order to locally test a subset of the triagebot commands, you need three components:

- A Zulip chat instance deployed on your local host
- The triagebot listening on your local host
- A Github repository to verify the commands sent by the Zulip chat

For commands that interact with a Github repository, you can set a test github repository and create a dedicated test [access token](https://github.com/settings/tokens/new) to send commands to it.

### Requirements

- Get a full Zulip installation [as a Docker container](https://github.com/zulip/docker-zulip):

  `$ docker pull zulip/docker-zulip`

- Configure Docker Compose for a full Zulip installation and configuration:
  `$ git clone https://github.com/zulip/docker-zulip.git && cd docker-zulip`

- Edit docker-compose.yml (as follows), this will let you conveniently access the Zulip Postgres DB and use it also for the triagebot:
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
  ```

- Pull all the containers
  `$ docker-compose start / docker-compose up -d`

- Check if the instance is up
  `$ curl -i http://localhost`

- Create Zulip organization
  `$ docker-compose exec -u zulip zulip /home/zulip/deployments/current/manage.py generate_realm_creation_link`

  and open the link received with a web browser. Once completed the wizard, the local Zulip instance is available. It cannot send emails unless you configure so, but it should not be needed for testing the triagebot.

- Create a bot hook on Zulip (retrieve the address of your Docker network interface with `ip addr show docker0`). Type of the bot is "webkook outgoing".

  ![screenshot](./zulip-bot-setup.png)

- Get the "zuliprc" and save it somewhere, example:
  ```
  [api]
  email=test-bot@localhost.localdomain
  key=gddqQu1bbOn6nX90a0LPV1kOa9kdBLpE
  site=https://localhost.localdomain
  token=OEuFkrQRhL2m4VKgHEczaKloa7Rw87av
  ```

## Run the bot

```bash
# export DATABASE_URL="postgres://zulip:zulip@172.29.0.2:5432/zulip
$ export ZULIP_TOKEN=OEuFkrQRhL2m4VKgHEczaKloa7Rw87av
$ export GITHUB_API_TOKEN=<YOUR_GITHUB_TOKEN>
$ cargo run --bin triagebot
```

## Zulip commands

To test interactions from Zulip to the triagebot, open on Zulip a private message session with it.

Commands from Zulip to the triagebot maps roughly to the following `cURL` call:

```bash
curl -XPOST \
    http://triagebot-host:8000/zulip-hook \
     -H "Host: 172.17.0.1:8000" \
     -H "token: the-zulip-bot-token" \
     -H "User-Agent: ZulipOutgoingWebhook/3.2" \
     -H "Accept-Encoding: gzip, deflate" \
     -H "Accept: */*" \
     -H "Connection: keep-alive" \
     -H "Content-Length: 849" \
     -H "Content-Type: application/json" \
     -d '{...payload...}'
```

The `payload` is a Zulip [Request](https://github.com/rust-lang/triagebot/blob/e60ffaddae21a8ad5763e4c8af3750c7151ae422/src/zulip.rs#L11-L33;) and contains command and parameters.

Example payload:
```json
{
  "data": "test",
  "token": "the-zulip-bot-token",
  "message": {
    "sender_id": 123456,
    "recipient_id": 123456,
    "sender_full_name": "Jon Asch",
    "type": "string"
  }
}
```

`sender_id` and `recipient_id` are Zulip ID, find [them here](https://github.com/rust-lang/team/tree/01392aee300df7df9fde50e3c259719309a93672/people).
