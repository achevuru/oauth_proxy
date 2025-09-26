# AKS OAuth Proxy

## Overview
The OAuth proxy is a FastAPI service that signs users in with Microsoft Entra using the authorization code flow with PKCE and exchanges their grant for user-scoped access tokens that target Azure Kubernetes Service (AKS). It is designed to run inside the same AKS cluster as the workloads it protects so that subsequent `kubectl` or Kubernetes API requests execute under the caller's identity while RBAC is enforced by the cluster. Workload identity is used to authenticate the proxy itself by presenting the federated token file mounted in the pod, avoiding the need for client secrets. 【F:design.md†L1-L33】【F:design.md†L47-L97】

### Key capabilities
* `/login` initiates the Microsoft Entra sign-in experience with the configured OIDC scopes and PKCE challenge.
* `/callback` finalises the authorization code exchange, persists the MSAL cache in the server-side session and acquires the AKS user token (prompting for incremental consent when required).
* `/whoami` returns the cached AKS token metadata and decoded claims for the signed-in user, automatically refreshing the token when it is close to expiry. 【F:app/main.py†L105-L251】

## Code flow
### 1. Initial `/login` request
- FastAPI routes the call to the `login` handler, which loads or creates a session bound to the signed cookie and purges expired entries so the request starts with a valid container.
- A PKCE verifier/challenge pair and cryptographically random `state` value are generated. The verifier stays server-side while the challenge and state are sent to Microsoft Entra to protect the later callback from interception or CSRF.
- A fresh MSAL confidential client is instantiated using the workload-identity client assertion from the federated token file so the proxy itself never stores long-lived secrets.
- MSAL composes the authorization request URL with the configured scopes, redirect URI, random state, “select account” prompt and PKCE challenge, defining what information is requested and binding the callback to this session.
- Before returning the `302` redirect, the session rotates its identifier, clears previous data and persists an `auth_flow` record (state, scopes, flow type, PKCE verifier, timestamp). The new cookie is written on the response so the callback can validate the returning code against these artifacts.
- The handler logs the redirect and commits the session, sending the browser to Microsoft Entra carrying the state and PKCE challenge that will anchor the forthcoming callback.

### 2. After Microsoft Entra redirects back
- The `/callback` handler reloads the session, checks for OAuth error parameters and validates both the `state` and stored PKCE verifier to ensure the response matches the initiation request before redeeming the authorization code.
- The MSAL token cache is rebuilt from the session, the confidential client is re-created and the authorization code is exchanged using the stored PKCE verifier and redirect URI. Any MSAL error results in a 400 response so callers know to restart the flow.
- On a first-time login, ID-token claims and account metadata are cached in the session for later silent token acquisition, and the serialised MSAL cache is persisted for subsequent requests.
- Immediately after redeeming the code, the proxy silently requests an AKS user-scoped token using the stored account. A successful response is written to the session (and the cache saved) before redirecting the user to `/whoami`; if MSAL indicates additional consent is needed, the proxy triggers an incremental-consent redirect using the same PKCE and state protections.

### 3. kubelogin fallback for delegated AKS tokens
When MSAL cannot mint the AKS token because the tenant requires admin consent, the proxy can offload the acquisition to the Microsoft first-party `kubelogin` client:

1. The callback (or `/whoami` refresh path) receives a `consent_required`/`interaction_required` error while requesting the AKS scope.
2. The proxy launches `kubelogin get-token --login devicecode --server-id <AKS app> --tenant-id <tenant> --client-id <public client>` in the background and stores the job identifier in the user’s session.
3. The user is redirected to `/kubelogin/device-code`, which polls the job:
   * If interaction is required, the endpoint returns the device-code instructions emitted by kubelogin so the user can finish the sign-in at `https://microsoft.com/devicelogin`.
   * Once kubelogin outputs an ExecCredential payload, the endpoint caches the AKS access token in the session and redirects to `/whoami`.
4. Later requests reuse the cached kubelogin token until it expires, at which point the proxy either refreshes it silently or starts a new kubelogin job if consent is still unavailable.

Kubelogin jobs are tracked per session; if the job fails or the session expires, `/kubelogin/device-code` responds with an error so the caller can restart the flow from `/login`.

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
| `KUBELOGIN_ENABLED` | Set to `false` to disable the kubelogin integration (enabled by default). |
| `KUBELOGIN_BINARY` | Override the kubelogin executable name/path if it is not already on `PATH`. |
| `KUBELOGIN_LOGIN` | Login mode supplied to kubelogin (defaults to `devicecode`). |
| `KUBELOGIN_CLIENT_ID` | Public client ID kubelogin should impersonate (defaults to the Microsoft AKS client). |
| `KUBELOGIN_ENVIRONMENT` | Azure cloud suffix passed to kubelogin (defaults to `AzurePublicCloud`). |

See `app/config.py` for the complete list of supported settings and defaults. 【F:app/config.py†L14-L97】

### Running the API server
After exporting the required environment variables, start the proxy with uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```
The root endpoint responds with a simple health payload, while `/login` kicks off the Microsoft Entra authorization flow.

### Testing
Automated test suites have not been implemented yet. Until they are added, validate changes manually by exercising the login flow and verifying the `/whoami` response against the target AKS cluster.

The `/login` endpoint is the entry point that initiates the Microsoft Entra OAuth flow. With the server running locally on port `8080`, you can use `curl` to observe the initial redirect and confirm that the session cookie is issued:

```bash
curl -i -c cookies.txt http://localhost:8080/login
```

The response should return `302 Found` with a `Location` header pointing at the Microsoft sign-in page and a `Set-Cookie` header for the proxy session. Complete the sign-in in a browser (or another HTTP client capable of following the redirect and handling the interactive login). After the identity provider redirects back to `/callback`, the proxy will finish exchanging the authorization code. You can then inspect the cached AKS token details with:

```bash
curl -b cookies.txt http://localhost:8080/whoami
```

### Triggering the kubelogin device-code flow
If the tenant has not pre-consented to the AKS delegated scope, the proxy falls back to kubelogin after `/callback` or `/whoami` fails to mint the token. To monitor the background job and complete the device-code instructions, call:

```bash
curl -i -b cookies.txt http://localhost:8080/kubelogin/device-code
```

The endpoint responds with one of the following:

* `302 Found` – kubelogin already produced an AKS token; follow the redirect to `/whoami` to see the result.
* `200 OK` with JSON – inspect the returned `message`, complete the device login at `https://microsoft.com/devicelogin`, then poll the endpoint again until the job finishes.
* `4xx/5xx` – the session expired or kubelogin returned an error; restart from `/login` after addressing the reported issue.

Once kubelogin succeeds, the `/whoami` response will include the user-scoped AKS token sourced from the plug-in, and the proxy will reuse it until it is refreshed or replaced.

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
