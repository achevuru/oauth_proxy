# Proxy Auth Design (AKS user-scoped tokens from a pod)

## 1. Goal (what this proxy does)

Expose a small HTTP service that:

- Signs users in with Microsoft Entra (Authorization Code flow + PKCE).
- Mints a user-scoped access token for AKS (`aud=6dae42f8-4368-4678-94ff-3960e28e3630`) using MSAL.
- Runs in-cluster (inside the same AKS) and can execute cluster actions (for example, run `kubectl` or call the Kubernetes API) as the signed-in user (RBAC enforced by AKS).
- Works with Workload Identity: the pod proves app identity via `client_assertion` from the federated token file (no client secrets).
- Supports multiple concurrent users or sessions and multi-browser logins.
- (Optional) Provides per-user rate limits and basic audit logs.

Non-goals (initially): full multi-cluster brokering, long-lived refresh token sync across replicas (we can add Redis later), group overage mitigation via Microsoft Graph calls, or SSO frontends.

## 2. High-level architecture

### Actors

- Browser user → hits the proxy's `/login`; completes Entra sign-in.
- Proxy (this service) → FastAPI/Flask app inside AKS; uses MSAL to redeem codes, store the token cache, and fetch AKS tokens.
- Microsoft Entra ID (STS) → issues ID and refresh tokens (for the app) and AKS user-scoped access tokens.
- AKS API server → validates bearer tokens, then authorizes using AKS RBAC or Azure RBAC for Kubernetes.

### Trust material

- Client assertion: read from `AZURE_FEDERATED_TOKEN_FILE` (Workload Identity) to authenticate the app (confidential client) to Entra.
- Cluster CA: for TLS to the in-cluster API server (usually `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`).

## 3. Auth flows (clean, predictable)

### 3.1. User sign-in (OIDC only)

1. `/login`: redirect to Entra with scopes `["openid", "profile", "offline_access"]` (no resource scopes).
2. `/callback`: redeem the auth code, receive the ID token (user identity) and refresh token, then persist `MSAL SerializableTokenCache` to the server session (or Redis) and store `home_account_id` in the session.

### 3.2. Acquire user-scoped AKS token

Rebuild the MSAL client with the same cache and call the AKS token acquisition flow.

