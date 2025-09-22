"""FastAPI application exposing the OAuth proxy endpoints."""

from __future__ import annotations

import logging
import secrets
import time
from pprint import pformat
from typing import Any, Dict, Optional

import msal
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .config import get_settings
from .msal_client import (
    build_cache_from_session,
    build_confidential_client,
    get_account_for_session,
    persist_cache_to_session,
)
from .pkce import create_pkce_pair
from .session import SessionManager
from .token_service import acquire_aks_token, needs_refresh
from .utils import decode_jwt_without_verification

logger = logging.getLogger(__name__)


settings = get_settings()
session_manager = SessionManager(
    cookie_name=settings.session_cookie_name,
    idle_timeout_seconds=settings.session_idle_timeout_seconds,
    absolute_timeout_seconds=settings.session_absolute_timeout_seconds,
    cookie_secure=settings.cookie_secure,
    cookie_samesite=settings.cookie_samesite,
)

AUTH_FLOW_KEY = "auth_flow"
AKS_TOKEN_KEY = "aks_token"


app = FastAPI(title="AKS OAuth Proxy", version="1.0.0")


def _log_flow_step(step: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Emit structured log entries for the OAuth flow steps."""

    if details:
        pretty_details = pformat(details, sort_dicts=True)
        logger.info("[OAuth flow] %s\n%s", step, pretty_details)
    else:
        logger.info("[OAuth flow] %s", step)


def _decode_token_for_logging(access_token: str) -> Dict[str, Any]:
    """Decode a JWT for logging without raising on failure."""

    try:
        return decode_jwt_without_verification(access_token)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("Failed to decode access token for logging: %s", exc)
        return {"error": str(exc)}


def _new_state() -> str:
    """Return a cryptographically random state parameter."""

    # ``secrets.token_urlsafe`` already returns a suitably random string
    # so we simply pass through its output. The helper provides a single
    # place to adjust the state generation strategy should we need to.
    return secrets.token_urlsafe(32)


def _store_user(session: Dict[str, Any], client: msal.ConfidentialClientApplication, result: Dict[str, Any]) -> Dict[str, Any]:
    # The MSAL client caches any accounts discovered during the
    # authorization-code exchange. We expect exactly one account for the
    # signed-in user; if MSAL returns nothing, something has gone wrong in
    # the upstream login process.
    accounts = client.get_accounts()
    if not accounts:
        raise HTTPException(status_code=500, detail="No account information returned from MSAL")

    account = accounts[0]
    claims = result.get("id_token_claims") or {}
    session["user"] = {
        "home_account_id": account.get("home_account_id"),
        "username": account.get("username"),
        "oid": claims.get("oid"),
        "tid": claims.get("tid"),
        "upn": claims.get("preferred_username"),
        "name": claims.get("name"),
        "id_token_claims": claims,
        "updated_at": int(time.time()),
    }
    return account


def _start_incremental_consent(
    handle,
    session: Dict[str, Any],
    client: msal.ConfidentialClientApplication,
    account: Dict[str, Any],
):
    # When the AKS token request fails because additional permissions are
    # required we kick off a fresh authorization flow. PKCE is required for
    # the public-client style redirect, so we generate a new verifier and
    # code challenge pair and persist the verifier in the session.
    verifier, challenge = create_pkce_pair()
    state = _new_state()
    session[AUTH_FLOW_KEY] = {
        "state": state,
        "scopes": [settings.aks_scope],
        "type": "consent",
        "code_verifier": verifier,
        "created_at": int(time.time()),
    }

    login_hint = account.get("username")
    auth_url = client.get_authorization_request_url(
        scopes=[settings.aks_scope],
        redirect_uri=settings.redirect_uri,
        state=state,
        prompt="consent",
        login_hint=login_hint,
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    # The PKCE verifier is stored in the session, while the challenge and
    # state travel with the redirect. Once the user completes the consent
    # prompt the callback handler will verify that they match.
    response = RedirectResponse(auth_url, status_code=302)
    _log_flow_step(
        "Starting incremental consent flow",
        {
            "authorization_url": auth_url,
            "scopes": [settings.aks_scope],
            "state": state,
            "user": {
                "home_account_id": account.get("home_account_id"),
                "username": account.get("username"),
            },
        },
    )
    handle.commit(response)
    return response


@app.get("/")
async def root() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/login")
async def login(request: Request):
    # Sessions are keyed on a signed cookie. ``load_session`` returns a
    # handle that lets us transparently update the underlying entry while
    # ensuring cookies are written back to the client.
    handle = session_manager.load_session(request)
    # PKCE protects the authorization-code flow for public clients. The
    # verifier must stay server-side whereas the challenge is sent to the
    # identity provider.
    verifier, challenge = create_pkce_pair()
    state = _new_state()
    # A new confidential client application is created for every request
    # so each handler operates with a fresh view of the MSAL cache.
    client = build_confidential_client()

    auth_url = client.get_authorization_request_url(
        scopes=settings.oidc_scopes,
        redirect_uri=settings.redirect_uri,
        state=state,
        prompt="select_account",
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    response = RedirectResponse(auth_url, status_code=302)
    # ``rotate`` assigns a brand new session identifier to avoid session
    # fixation and clears any leftover data from previous logins.
    session = handle.rotate(response)
    session.clear()
    session[AUTH_FLOW_KEY] = {
        "state": state,
        "scopes": settings.oidc_scopes,
        "type": "login",
        "code_verifier": verifier,
        "created_at": int(time.time()),
    }
    _log_flow_step(
        "Initiating login redirect",
        {
            "authorization_url": auth_url,
            "pkce": {
                "code_challenge": challenge,
            },
            "scopes": settings.oidc_scopes,
            "state": state,
        },
    )
    handle.commit(response)
    return response


@app.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None):
    handle = session_manager.load_session(request)
    session = handle.data

    if error:
        raise HTTPException(status_code=400, detail=f"Authorization error: {error}: {error_description}")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing authorization code or state")

    flow = session.get(AUTH_FLOW_KEY)
    if not flow or flow.get("state") != state:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    verifier = flow.get("code_verifier")
    if not verifier:
        raise HTTPException(status_code=400, detail="Missing PKCE verifier in session")

    scopes = flow.get("scopes") or settings.oidc_scopes

    _log_flow_step(
        "Processing authorization callback",
        {
            "authorization_code": code,
            "flow_type": flow.get("type"),
            "scopes": scopes,
            "state": state,
        },
    )

    # Rehydrate the MSAL token cache from the session data before creating
    # the client so that MSAL can correlate the authorization response with
    # previous requests.
    cache = build_cache_from_session(session)
    client = build_confidential_client(cache)

    # Exchange the authorization code for tokens while validating the PKCE
    # verifier that was stored in the session during the initial redirect.
    token_result = client.acquire_token_by_authorization_code(
        code,
        scopes=scopes,
        redirect_uri=settings.redirect_uri,
        code_verifier=verifier,
    )

    if "error" in token_result:
        description = token_result.get("error_description") or token_result["error"]
        raise HTTPException(status_code=400, detail=f"Token acquisition failed: {description}")

    _log_flow_step(
        "Authorization code exchanged for tokens",
        {
            "authorization_code": code,
            "expires_on": token_result.get("expires_on"),
            "flow_type": flow.get("type"),
            "scope": token_result.get("scope"),
            "state": state,
        },
    )

    persist_cache_to_session(cache, session)

    if flow.get("type") == "login":
        # For initial sign-ins MSAL has just stored the account metadata in
        # its cache. We extract that information and persist it alongside the
        # session so future requests can locate the correct account.
        account = _store_user(session, client, token_result)
        _log_flow_step(
            "User information cached in session",
            {
                "user": {
                    "home_account_id": session["user"].get("home_account_id"),
                    "username": session["user"].get("username"),
                }
            },
        )
    else:
        # Incremental consent flows do not replace the logged-in user, so we
        # look up the previously cached account for the current session.
        account = get_account_for_session(client, session)
        if not account:
            raise HTTPException(status_code=400, detail="User session not initialised")

    session.pop(AUTH_FLOW_KEY, None)

    # Try to obtain the downstream AKS token immediately so the user lands
    # on the "whoami" endpoint with a valid token in hand.
    token_entry, interaction_error = acquire_aks_token(client, account)
    if token_entry:
        session[AKS_TOKEN_KEY] = token_entry
        persist_cache_to_session(cache, session)
        _log_flow_step(
            "AKS access token acquired",
            {
                "expires_on": token_entry.get("expires_on"),
                "scope": token_entry.get("scope"),
                "token_claims": _decode_token_for_logging(token_entry["access_token"]),
            },
        )
        response = RedirectResponse(url="/whoami", status_code=302)
        handle.commit(response)
        return response

    session.pop(AKS_TOKEN_KEY, None)
    if interaction_error in {"interaction_required", "consent_required"}:
        _log_flow_step(
            "AKS token requires additional consent",
            {"interaction_error": interaction_error},
        )
        response = _start_incremental_consent(handle, session, client, account)
        persist_cache_to_session(cache, session)
        return response

    logger.error("Unable to acquire AKS token: %s", interaction_error)
    raise HTTPException(status_code=500, detail="Failed to acquire AKS token")


@app.get("/whoami")
async def whoami(request: Request):
    handle = session_manager.load_session(request)
    session = handle.data

    user = session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="User is not signed in")

    token_entry = session.get(AKS_TOKEN_KEY)
    if needs_refresh(token_entry):
        # Refreshing requires the MSAL cache; we rebuild the client with the
        # cached state and then silently request a new token.
        cache = build_cache_from_session(session)
        client = build_confidential_client(cache)
        account = get_account_for_session(client, session)
        if not account:
            raise HTTPException(status_code=401, detail="User session not initialised")
        token_entry, interaction_error = acquire_aks_token(client, account)
        if not token_entry:
            session.pop(AKS_TOKEN_KEY, None)
            if interaction_error in {"interaction_required", "consent_required"}:
                raise HTTPException(status_code=401, detail="Additional consent required")
            raise HTTPException(status_code=500, detail="Failed to acquire AKS token")
        session[AKS_TOKEN_KEY] = token_entry
        persist_cache_to_session(cache, session)
        _log_flow_step(
            "AKS access token refreshed",
            {
                "expires_on": token_entry.get("expires_on"),
                "scope": token_entry.get("scope"),
                "token_claims": _decode_token_for_logging(token_entry["access_token"]),
            },
        )

    aks_token = session.get(AKS_TOKEN_KEY)
    try:
        # Only the downstream services validate the token signature. For the
        # informational "whoami" response we decode the JWT locally without
        # verification to surface useful claims to the caller.
        claims = decode_jwt_without_verification(aks_token["access_token"])
    except Exception as exc:  # pragma: no cover - indicates malformed token
        raise HTTPException(status_code=500, detail="Stored AKS token is invalid") from exc

    _log_flow_step(
        "Returning AKS access token information",
        {
            "expires_on": aks_token.get("expires_on"),
            "scope": aks_token.get("scope"),
            "token_claims": claims,
        },
    )

    response_payload = {
        "user": {
            "home_account_id": user.get("home_account_id"),
            "username": user.get("username"),
            "oid": user.get("oid"),
            "upn": user.get("upn"),
        },
        "aks_token": {
            "expires_on": aks_token.get("expires_on"),
            "scope": aks_token.get("scope"),
            "claims": {
                "aud": claims.get("aud"),
                "iss": claims.get("iss"),
                "oid": claims.get("oid"),
                "upn": claims.get("upn"),
                "idtyp": claims.get("idtyp"),
            },
        },
    }

    response = JSONResponse(response_payload)
    handle.commit(response)
    return response

