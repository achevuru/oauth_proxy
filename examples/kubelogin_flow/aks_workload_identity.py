"""Exchange a workload identity token for an AKS access token.

This script mirrors kubelogin's workload-identity login by presenting the
service account token issued by Kubernetes to Azure AD and exchanging it for
an AKS user token targeting the managed cluster resource.

Run it from a pod (or any environment) configured for Azure Workload Identity.

Usage:
    export AZURE_CLIENT_ID=<federated workload app client id>
    export AZURE_TENANT_ID=<tenant guid>
    export AZURE_FEDERATED_TOKEN_FILE=/var/run/secrets/azure/tokens/azure-identity-token
    python examples/kubelogin_flow/aks_workload_identity.py

Optional environment variables:
    AKS_SERVER_APP_ID   Server application (resource) ID. Defaults to the
                        Microsoft AKS server app (6dae42f8-4368-4678-94ff-3960e28e3630).
    AZURE_SCOPE         Explicit scope string. Overrides AKS_SERVER_APP_ID when
                        provided.
    AZURE_AUTHORITY_HOST Azure cloud authority host. Defaults to the value
                        implied by AZURE_CLOUD or https://login.microsoftonline.com.
    AZURE_CLOUD         Friendly cloud name (AzurePublicCloud, AzureUSGovernment,
                        AzureChinaCloud). Ignored when AZURE_AUTHORITY_HOST is set.

The script requires the ``azure-identity`` package:
    pip install azure-identity
"""
from __future__ import annotations

import os
import sys

from azure.identity import AzureAuthorityHosts, WorkloadIdentityCredential


CLOUD_AUTHORITIES = {
    "azurepubliccloud": AzureAuthorityHosts.AZURE_PUBLIC_CLOUD,
    "azureusgovernment": AzureAuthorityHosts.AZURE_GOVERNMENT,
    "azurechinacloud": AzureAuthorityHosts.AZURE_CHINA,
}


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        print(f"Environment variable {name} is required.", file=sys.stderr)
        sys.exit(1)
    return value


def _resolve_authority_host() -> str:
    explicit = os.getenv("AZURE_AUTHORITY_HOST")
    if explicit:
        return explicit

    cloud = os.getenv("AZURE_CLOUD", "AzurePublicCloud").lower()
    authority = CLOUD_AUTHORITIES.get(cloud)
    if not authority:
        supported = ", ".join(sorted(CLOUD_AUTHORITIES))
        raise ValueError(
            f"Unsupported AZURE_CLOUD '{cloud}'. Supported values: {supported}."
        )
    return authority


def _resolve_scope(server_app_id: str) -> str:
    scope_override = os.getenv("AZURE_SCOPE")
    if scope_override:
        return scope_override
    return f"{server_app_id}/.default"


def main() -> None:
    client_id = _require_env("AZURE_CLIENT_ID")
    tenant_id = _require_env("AZURE_TENANT_ID")
    token_file = _require_env("AZURE_FEDERATED_TOKEN_FILE")
    server_app_id = os.getenv(
        "AKS_SERVER_APP_ID", "6dae42f8-4368-4678-94ff-3960e28e3630"
    )

    scope = _resolve_scope(server_app_id)
    authority_host = _resolve_authority_host()

    credential = WorkloadIdentityCredential(
        client_id=client_id,
        tenant_id=tenant_id,
        token_file_path=token_file,
        authority_host=authority_host,
    )

    token = credential.get_token(scope)

    print("Successfully obtained AKS access token via workload identity.")
    print(f"Token expires on: {token.expires_on}")
    access_token = token.token
    print("Access token (truncated):")
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
