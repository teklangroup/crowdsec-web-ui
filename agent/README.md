# crowdsec-fleet-agent

A small agent for each CrowdSec host. It reports health, versions, bouncers,
machines, hub collections, local decisions and recent alerts to the **Fleet**
page in CrowdSec Web UI, and runs the actions queued there.

- **Outbound only.** The agent polls the UI every 15 seconds, so hosts need no
  open ports and the LAPI never has to be exposed.
- **No remote shell.** The UI can only send named actions (`ban`, `unban`,
  `hub_install`, `hub_remove`, `hub_update`, `hub_upgrade`, `reload`,
  `refresh`). The agent validates every parameter again and runs a fixed
  `cscli` argument list without a shell.
- **Per-host keys.** The shared enrollment token is used once. After that,
  each host authenticates with its own key, and removing the host in the UI
  revokes the key.

## Install

Turn the feature on in the UI's config (`fleet.enabled: true` or
`CONFIG_FLEET_ENABLED=true`), then copy the enrollment token from the Fleet
page.

```sh
make release   # dist/crowdsec-fleet-agent-linux-{amd64,arm64,armv7}

sudo install -m755 dist/crowdsec-fleet-agent-linux-amd64 /usr/local/bin/crowdsec-fleet-agent
sudo mkdir -p /etc/crowdsec-fleet
sudo cp deploy/agent.env.example /etc/crowdsec-fleet/agent.env   # then edit it
sudo cp deploy/crowdsec-fleet-agent.service /etc/systemd/system/
sudo systemctl enable --now crowdsec-fleet-agent
```

For CrowdSec in Docker, set `FLEET_CSCLI="docker exec crowdsec cscli"` and
`FLEET_RELOAD_CMD="docker restart crowdsec"`.

## Options

| Flag | Environment | Default |
| --- | --- | --- |
| `-server` | `FLEET_SERVER` | required; include any base path |
| `-enroll-token` | `FLEET_ENROLL_TOKEN` | first run only |
| `-tags` | `FLEET_TAGS` | none |
| `-instance` | `FLEET_INSTANCE` | none; links the host to a configured LAPI instance |
| `-hostname` | `FLEET_HOSTNAME` | system hostname |
| `-cscli` | `FLEET_CSCLI` | `cscli` |
| `-reload-cmd` | `FLEET_RELOAD_CMD` | `systemctl reload crowdsec` |
| `-state` | `FLEET_STATE` | `/var/lib/crowdsec-fleet/agent.json` |
| `-interval` | | `15s` |
| `-snapshot-every` | | `60s` |
| `-insecure-skip-verify` | | `false` (testing only) |

## Development

```sh
make test
```
