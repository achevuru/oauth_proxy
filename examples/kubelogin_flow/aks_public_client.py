"""Obtain an AKS user token using the kubelogin public client ID.

This script mirrors the kubelogin delegated flow by authenticating a user
through the Microsoft Authentication Library (MSAL) public client
registration that AKS uses by default. It supports silent cache re-use and
falls back to device-code authentication when an interactive login is
required.

Usage:
    export AZURE_TENANT_ID=<tenant-guid>
    python examples/kubelogin_flow/aks_public_client.py

Optional environment variables:
    AKS_SERVER_APP_ID   Server application (resource) ID. Defaults to the
                        Microsoft AKS server app (6dae42f8-4368-4678-94ff-3960e28e3630).
    MSAL_CACHE_PATH     Location to store the serialized MSAL cache. Defaults
                        to ~/.cache/aks_public_client_token.json.
    AZURE_CLOUD         Name of the Azure cloud (AzurePublicCloud,
                        AzureUSGovernment, AzureChinaCloud). Defaults to
                        AzurePublicCloud.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import Any, Dict

import msal

# Microsoft-managed public client ID used by kubelogin.
PUBLIC_CLIENT_ID = "80faf920-1908-4b52-b5ef-a8e7bedfc67a"

# Mapping of Azure cloud names to their login authorities.
CLOUD_AUTHORITIES = {
    "azurepubliccloud": "https://login.microsoftonline.com/",
    "azureusgovernment": "https://login.microsoftonline.us/",
    "azurechinacloud": "https://login.chinacloudapi.cn/",
}


def get_environment_variable(name: str) -> str:
    """Fetch an environment variable and exit with guidance if missing."""
    value = os.getenv(name)
    if not value:
        print(
            f"Environment variable {name} is required. Set it before running this script.",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def resolve_authority(tenant_id: str) -> str:
    cloud = os.getenv("AZURE_CLOUD", "AzurePublicCloud").lower()
    base = CLOUD_AUTHORITIES.get(cloud)
    if not base:
        supported = ", ".join(sorted(CLOUD_AUTHORITIES))
        raise ValueError(
            f"Unsupported AZURE_CLOUD '{cloud}'. Supported values: {supported}."
        )
    return base + tenant_id


def load_cache(cache_path: pathlib.Path) -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if cache_path.exists():
        cache.deserialize(cache_path.read_text())
    return cache


def save_cache(cache: msal.SerializableTokenCache, cache_path: pathlib.Path) -> None:
    if cache.has_state_changed:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(cache.serialize())


def acquire_aks_token(app: msal.PublicClientApplication, scope: str) -> Dict[str, Any]:
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent([scope], account=accounts[0])
        if result and "access_token" in result:
            return result

    flow = app.initiate_device_flow(scopes=[scope])
    if "user_code" not in flow:
        raise RuntimeError(f"Failed to create device flow: {json.dumps(flow, indent=2)}")

    print(flow["message"])  # Instructions for the user.
    result = app.acquire_token_by_device_flow(flow)
    if not result or "access_token" not in result:
        raise RuntimeError(f"Failed to obtain token: {json.dumps(result, indent=2)}")
    return result


def main() -> None:
    tenant_id = get_environment_variable("AZURE_TENANT_ID")
    server_app_id = os.getenv(
        "AKS_SERVER_APP_ID", "6dae42f8-4368-4678-94ff-3960e28e3630"
    )
    scope = f"{server_app_id}/.default"

    cache_path = pathlib.Path(
        os.getenv("MSAL_CACHE_PATH", pathlib.Path.home() / ".cache/aks_public_client_token.json")
    )
    cache = load_cache(cache_path)

    authority = resolve_authority(tenant_id)
    app = msal.PublicClientApplication(
        client_id=PUBLIC_CLIENT_ID,
        authority=authority,
        token_cache=cache,
    )

    result = acquire_aks_token(app, scope)
    save_cache(cache, cache_path)

    user = result.get("id_token_claims", {}).get("name") or "<unknown>"
    print("\nSuccessfully obtained AKS delegated token.")
    print(f"User: {user}")
    print(f"Expires on: {result.get('expires_on')}")
    print("Access token (truncated):")
    access_token = result["access_token"]
    print(access_token[:40] + "..." + access_token[-10:])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Aborted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - surface clear errors for operators
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
