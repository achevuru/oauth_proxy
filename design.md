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

Rebuild the MSAL client with the same cache and call the AKS token acquisition flow:

```python
acquire_token_silent(["6dae42f8-4368-4678-94ff-3960e28e3630/.default"], account=<by home_account_id>)
```

If silent returns `None`, do a one-time incremental consent redirect for the AKS scope and repeat the silent call after the callback. (If you pre-grant the app the AKS delegated permission `user_impersonation`, silent works immediately—no consent hop.)

### 3.3. Call Kubernetes API / `kubectl` (as the user)

From a pod, either:

- Use the in-cluster endpoint with the cluster CA and `--token $AKS_USER_TOKEN`, or
- Use a kubeconfig with embedded CA and override the user token.

AKS validates TLS first, then validates your Entra JWT (`aud=AKS`, issuer=tenant, signature). RBAC is evaluated on the user identity in the token.

## 4. Endpoints (MVP)

- `GET /login` → start OIDC sign-in.
- `GET /callback?code=&state=` → finish OIDC or AKS-consent step; on success, cache has user + refresh; try silent AKS token; store `aks_token` in session.
- `GET /whoami` → return decoded AKS token claims (`aud`/`iss`/`oid`/`upn`/`idtyp`).
- `POST /kubectl` (optional) → execute a whitelisted `kubectl` (e.g., `auth can-i`, `get pods -n <ns>`), injecting `--token $AKS_USER_TOKEN` and the correct CA.
- `POST /api/k8s/*` (optional) → direct API calls proxied with `Authorization: Bearer <AKS_USER_TOKEN>`.

## 5. Session & token cache

Server-side sessions (cookie only holds a random SID; session state in process or Redis).

Store:

- `home_account_id`, UPN, OID, timestamps
- MSAL cache blob (serialized) per session
- `aks_token` (short-lived; may be re-acquired silently)
- Idle timeout (e.g., 30 min); absolute lifetime (e.g., 8 hrs). Rotate session ID at login.

## 6. Consent model

Preferred: pre-grant AKS delegated permission to your client app (App Registration → API permissions → Azure Kubernetes Service AAD Server → Delegated → `user_impersonation` → Grant admin consent). Then `/.default` is silent.

Otherwise: handle incremental consent once—if silent fails, redirect with `scopes=[AKS_APP/user_impersonation]` + `prompt=consent`. After callback, future silent works. (This mirrors Microsoft’s guidance on incremental consent & “UI required” paths.)

## 7. Workload Identity (confidential client with `client_assertion`)

Pod has `AZURE_FEDERATED_TOKEN_FILE`. Read it and set:

```python
client_credential = {
  "client_assertion": <file contents>,
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
}
```

## 8. TLS & kube access

- If calling the in-cluster API endpoint: pass `--certificate-authority /var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
- If using the public FQDN: ensure your container has `ca-certificates` (or use kubeconfig with embedded CA).
- The token’s audience must be the AKS server app (`6dae42f8-4368-4678-94ff-3960e28e3630`). Tools like `kubelogin`/exec-plugin do the same thing under the hood, targeting that server ID.

## 9. Security notes

- Cookies: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`); rotate at login.
- Never send refresh/access tokens to the browser; keep them server-side.
- Validate `state` (and `nonce` if you add it) on callback.
- Limit `kubectl` to a safe allowlist of subcommands/flags.
- Log request IDs + user OID (not raw tokens) for audit.

## 10. Rate limiting (optional MVP)

Per-user sliding window (e.g., 60 requests/min). Key on `home_account_id`. Store counters in Redis or in-process if single-instance.

## 11. Config (env)

- `TENANT_ID`, `CLIENT_ID`, `REDIRECT_URI`
- `AZURE_FEDERATED_TOKEN_FILE`
- `SESSION_SECRET`
- (Optional) `KUBE_API_SERVER`, `KUBE_CA_FILE`

## 12. Failure modes & handling

- `MsalUiRequiredException` / silent returns `None` → trigger incremental consent flow for `AKS_APP/user_impersonation` (one-time).
- `401/403` from API server → check `aud=AKS`, user vs. app token (`idtyp` must not be "app"), RBAC bindings.
- “cert signed by unknown authority” → supply cluster CA or use kubeconfig with CA embedded.
- Empty `get_accounts()` → you’re not restoring the same MSAL cache; fix cache persistence.

## 13. Minimal sequence diagram (text)

```text
Browser -> Proxy (/login): start OIDC
Proxy -> Entra: authorize (openid profile offline_access)
Entra -> Browser -> Proxy (/callback?code=...): auth code
Proxy -> Entra: redeem code (client_assertion)
Entra -> Proxy: ID token + refresh token (app-scoped AT irrelevant)
Proxy: store session + MSAL cache
Proxy -> Entra (MSAL silent): AKS /.default (user-scoped)
Entra -> Proxy: AKS user token
Proxy -> Kube API: Bearer <AKS token> (+ CA)
Kube API -> Proxy: authorized as that user (RBAC)
```

## 14. Implementation sketch (one-liners)

- `/login` → `get_authorization_request_url(scopes=OIDC_SCOPES)`
- `/callback` → `acquire_token_by_authorization_code(OIDC_SCOPES)` → save cache + `home_account_id`
- Get AKS token → `acquire_token_silent([AKS_APP/.default], account=by_home_account_id)` (redirect once with `prompt=consent` if needed)
- Call API/`kubectl` → inject `Authorization: Bearer <AKS_USER_TOKEN>` and the correct CA.
