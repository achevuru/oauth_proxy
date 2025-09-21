# AKS OAuth Proxy

## Overview
The OAuth proxy is a FastAPI service that signs users in with Microsoft Entra using the authorization code flow with PKCE and exchanges their grant for user-scoped access tokens that target Azure Kubernetes Service (AKS). It is designed to run inside the same AKS cluster as the workloads it protects so that subsequent `kubectl` or Kubernetes API requests execute under the caller's identity while RBAC is enforced by the cluster. Workload identity is used to authenticate the proxy itself by presenting the federated token file mounted in the pod, avoiding the need for client secrets. 【F:design.md†L1-L33】【F:design.md†L47-L97】

### Key capabilities
* `/login` initiates the Microsoft Entra sign-in experience with the configured OIDC scopes and PKCE challenge.
* `/callback` finalises the authorization code exchange, persists the MSAL cache in the server-side session and acquires the AKS user token (prompting for incremental consent when required).
* `/whoami` returns the cached AKS token metadata and decoded claims for the signed-in user, automatically refreshing the token when it is close to expiry. 【F:app/main.py†L105-L251】

## Project structure
```
.
├── app/                # FastAPI application and supporting modules
├── chart/              # Helm chart for deploying the proxy to Kubernetes
├── Dockerfile          # Container build for uvicorn-based deployment
├── design.md           # End-to-end design notes and flows
└── requirements.txt    # Python runtime dependencies
```

## Local development
### Prerequisites
* Python 3.11+
* Access to a Microsoft Entra tenant, app registration and AKS cluster configured for workload identity.
* A federated workload identity token file to authenticate the proxy (normally injected into pods via `AZURE_FEDERATED_TOKEN_FILE`).

### Installing dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
The project depends on FastAPI, uvicorn and the Microsoft Authentication Library (MSAL). 【F:requirements.txt†L1-L3】

### Required environment variables
The application reads its configuration exclusively from environment variables. At a minimum set the following before launching the service:

| Variable | Description |
| --- | --- |
| `TENANT_ID` | Microsoft Entra tenant identifier used to build the authority URL. |
| `CLIENT_ID` | Application (client) ID of the registered confidential client. |
| `REDIRECT_URI` | Redirect URI registered for the proxy; must match the URL served by `/callback`. |
| `SESSION_SECRET` | Secret key for signing and encrypting server-side session data. |
| `AZURE_FEDERATED_TOKEN_FILE` | Path to the workload identity token file used to authenticate the proxy via client assertions. |
| `SESSION_COOKIE_NAME` | Optional override of the session cookie name (`proxy_session` by default). |
| `SESSION_IDLE_TIMEOUT_SECONDS` | Optional idle timeout in seconds before a session expires (default 30 minutes). |
| `SESSION_ABSOLUTE_TIMEOUT_SECONDS` | Optional absolute session lifetime in seconds (default 8 hours). |
| `SESSION_COOKIE_SECURE` / `SESSION_COOKIE_SAMESITE` | Optional flags controlling cookie security attributes. |

See `app/config.py` for the complete list of supported settings and defaults. 【F:app/config.py†L14-L97】

### Running the API server
After exporting the required environment variables, start the proxy with uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```
The root endpoint responds with a simple health payload, while `/login` kicks off the Microsoft Entra authorization flow.

### Testing
Automated test suites have not been implemented yet. Until they are added, validate changes manually by exercising the login flow and verifying the `/whoami` response against the target AKS cluster.

## Container image
A production-friendly container image can be built from the provided Dockerfile:
```bash
docker build -t ghcr.io/your-org/oauth-proxy:local .
```
The image installs the Python dependencies, copies the FastAPI application and runs uvicorn on port 8080 as an unprivileged user. 【F:Dockerfile†L2-L30】

To run the container locally, supply the same environment variables and mount a federated token file that MSAL can use for client assertions:
```bash
docker run --rm -p 8080:8080 \
  -e TENANT_ID=... \
  -e CLIENT_ID=... \
  -e REDIRECT_URI=http://localhost:8080/callback \
  -e SESSION_SECRET=change-me \
  -e AZURE_FEDERATED_TOKEN_FILE=/tokens/assertion.jwt \
  -v $PWD/local-token.jwt:/tokens/assertion.jwt \
  ghcr.io/your-org/oauth-proxy:local
```

## Deploying to Kubernetes with Helm
A Helm chart is available under `chart/oauth-proxy` to deploy the proxy into AKS (or any Kubernetes cluster). Key values to set include:

* `image.repository` / `image.tag` – reference to the published container image.
* `settings.tenantId`, `settings.clientId`, `settings.redirectUri` – Microsoft Entra configuration passed as environment variables.
* `serviceAccount.azureWorkloadIdentity.*` – enable and configure Azure Workload Identity so the pod receives the federated token file.
* `sessionSecret.*` – provide the session secret either inline or via an existing Kubernetes secret.
* `settings.session*` fields – customise cookie properties and timeouts.
* `ingress.*` – expose the proxy externally if required.

Refer to `values.yaml` for the full set of tunable options, including probes, autoscaling and resource requests. 【F:chart/oauth-proxy/values.yaml†L1-L99】

Install or upgrade the release with:
```bash
helm upgrade --install oauth-proxy chart/oauth-proxy \
  --set image.repository=ghcr.io/your-org/oauth-proxy \
  --set image.tag=1.0.0 \
  --set settings.tenantId=<tenant> \
  --set settings.clientId=<client> \
  --set settings.redirectUri=https://your-host/callback \
  --set sessionSecret.value=$(openssl rand -hex 32)
```
If you already store the session secret in a managed secret, set `sessionSecret.existingSecret` and omit `sessionSecret.value`.

## Additional resources
* Review `design.md` for deep-dive context on the end-to-end flow, session handling and security recommendations. 【F:design.md†L1-L144】
* Azure documentation on [Workload Identity](https://learn.microsoft.com/azure/aks/workload-identity-overview) and [AKS user authentication](https://learn.microsoft.com/azure/aks/managed-aad) provides further background on the underlying platform features.
