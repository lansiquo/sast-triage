# Decision 0001: hosting and trust for the live deployment

- Status: decided
- Date: 2026-11-12
- Decided by: Robin (owner)
- Roadmap item: F-2.1, "Decide hosting and trust" ([ROADMAP.md](../../ROADMAP.md), Step 2)

This record says where the durable-mode GitHub App service will run and answers each trust question with a yes or a no. It records a decision. It deploys nothing and authorizes no action: see "Not decided here / not authorized" below.

## Decision

Durable mode will run as a self-hosted lab service on one dedicated Linux VM, separate from other workloads.

- The VM opens no inbound ports.
- GitHub reaches the service at exactly one HTTPS webhook endpoint, through a tunnel that the VM opens outbound.
- The App private key and the webhook secret are kept only in the VM's secret store, readable by the worker account alone.
- The GitHub App installation is narrowed to the repositories the service scans.

## Each question, yes or no

| Question | Answer |
|---|---|
| Self-hosted? | Yes |
| Hosted multi-tenant service? | No |
| One dedicated VM, separate from other workloads? | Yes |
| Inbound ports open on the host? | No |
| Exactly one HTTPS webhook endpoint, reachable through an outbound tunnel? | Yes |
| App private key and webhook secret only in the host's secret store, readable by the worker account alone? | Yes |
| App installation narrowed to the repositories it scans? | Yes |

The sixth answer differs from the current design on one point, the webhook secret: see "Existing statements that differ", point 1.

## Option not chosen

A hosted multi-tenant service: one deployment, run for many accounts and repositories.

Why not: the service supports one repository and one installation per deployment, on a SQLite queue with one worker ([ARCHITECTURE.md](../../ARCHITECTURE.md), "Components" and "Out of scope"). A multi-tenant service needs tenant isolation (F-5.2), routing by installation (F-5.3) and a datastore beyond single-host SQLite (Step 7); none is built, and each still needs an owner decision.

## Not decided here / not authorized

Each of these needs a separate owner approval before it happens. This record gives none of them.

- **Provisioning:** creating, installing or configuring the VM or its service accounts.
- **Tunnel setup:** choosing a tunnel, configuring it or starting it.
- **Credential moves:** placing or copying the App private key or the webhook secret on any host.
- **App setting changes:** the installation's repository list, permissions, event subscriptions or webhook URL.
- **Network changes:** any change to what can reach the host or what the host can reach.

The other Step 2 items (F-2.2 to F-2.5) are separate decisions. The approval gates and the required release verification in [deploy/README.md](../../deploy/README.md) still apply: until they pass, the service is not deployed.

## Existing statements that differ

The decision was compared with [ARCHITECTURE.md](../../ARCHITECTURE.md) and the documents in `deploy/` as they stood on 2026-11-12. This record changes none of them. Three points differ.

### 1. Which account reads the webhook secret (not resolved here)

The decision keeps the webhook secret readable by the worker account alone. The current design gives it to the web listener, which runs as a second account, and keeps it from the worker:

- `ARCHITECTURE.md`, "Trust boundaries": the web listener "holds only the webhook secret and queue access, runs as its own OS user".
- `deploy/README.md`, "Architecture", about the listener: "Holds the webhook secret, never the PEM."
- `deploy/trust-boundaries.md`, "Credential ownership": the web listener "receives the webhook secret and verifies HMAC".
- `deploy/production-operations.md`, "Configuration and isolated Linux acceptance": "Web must receive webhook secrets", and the worker must receive "no webhook secret". `deploy/check_environment.py` enforces both: `--role web` fails without a webhook secret, and `--role worker` fails with one.

The App private key is not affected: in the decision and in the current design, only the worker account reads it. The two statements about the webhook secret cannot both hold, and this record does not choose between them. Which account reads it is an owner decision, needed before the webhook secret is placed on a host.

### 2. Installation scope

- `deploy/README.md`, "Integration target": the installation "covers all the account's repositories with broad permissions", and "The App's private key is not limited".

Both describe today's installation. Under the decision the installation covers only the repositories the service scans. They stay true until an approved App setting change, and are out of date after it. `ARCHITECTURE.md`, "Security controls" already says each installation token is narrowed to the deployment's one repository, which agrees with the decision.

### 3. How the webhook endpoint is reached

- `deploy/README.md`, "Architecture" and "Install and run": the listener is "behind an HTTPS proxy", and "Expose only the proxy's HTTPS listener". Neither says how GitHub reaches that listener. Under the decision it is through the outbound tunnel, never through an inbound port.
- `deploy/README.md`, "Approval gates", gate 1: "no paid provider, tunnel or network expansion is authorized". Still true, because this record authorizes no tunnel setup, but a tunnel is now the chosen way in.
- `deploy/README.md`, "Required release verification": "Check HTTPS `/health` and `/ready`". Under the decision the webhook is the only endpoint reachable from outside the VM, so `/health` and `/ready` cannot be checked through the public endpoint.

Other documents in `deploy/` repeat these three points in their own words and are not listed one by one. Nothing else that was checked disagrees with the decision: the dedicated VM kept separate from other workloads, the worker as the only reader of the App private key, Uvicorn bound to the loopback interface, and the statements that no host or credential is provisioned.
