# kubelogin-style AKS token acquisition

This example mirrors kubelogin's **workload identity** login mode so you can
exercise the same flow the proxy uses inside a pod. Instead of prompting a user,
it exchanges the federated token mounted by Azure Workload Identity for a
delegated AKS access token.

## Prerequisites

* An Azure Kubernetes Service cluster with [workload identity](https://learn.microsoft.com/azure/aks/workload-identity-overview)
  enabled.
* A service account annotated for workload identity with the client ID and
  tenant ID of the Microsoft Entra application registration you want to use.
* The pod running this script must have access to the federated token file (for
  example `/var/run/secrets/azure/tokens/azure-identity-token`).
* Install the Azure Identity SDK:

  ```bash
  pip install azure-identity
  ```

## Running the script

1. Start a pod (or container) with the workload identity environment variables
   exported. Azure injects these automatically when the service account is
   configured correctly, but you can export them manually for testing:

   ```bash
   export AZURE_CLIENT_ID="<workload identity app client id>"
   export AZURE_TENANT_ID="<tenant guid>"
   export AZURE_FEDERATED_TOKEN_FILE="/var/run/secrets/azure/tokens/azure-identity-token"
   ```

2. Optionally override the AKS resource or scope:

   ```bash
   export AKS_SERVER_APP_ID="6dae42f8-4368-4678-94ff-3960e28e3630"  # default
   # export AZURE_SCOPE="6dae42f8-4368-4678-94ff-3960e28e3630/User.Read"
   ```

3. Run the helper:

   ```bash
   python examples/kubelogin_flow/aks_workload_identity.py
   ```

The script will exchange the federated token for an access token targeting the
AKS resource (`<server-app-id>/.default` unless you supplied an explicit scope).
It prints the expiration time and a truncated view of the resulting access
token so you can confirm the flow completed successfully.

### Verifying the prerequisites

If the script fails with an authorization error, double-check that:

* The Microsoft Entra application tied to your workload identity has been
  granted delegated access to the **Azure Kubernetes Service AAD Server**
  resource (either via the portal or `az ad app permission add`).
* The service account annotation matches the client ID you exported and the pod
  is reading the federated token file mounted by Azure Workload Identity.
* `AKS_SERVER_APP_ID` points at the server application backing your AKS
  cluster. The default (`6dae42f8-4368-4678-94ff-3960e28e3630`) targets the
  Microsoft-managed AKS resource.

## Customizing the authority

If you need to target a sovereign cloud, set either:

* `AZURE_CLOUD` to one of `AzurePublicCloud` (default), `AzureUSGovernment`, or
  `AzureChinaCloud`, or
* `AZURE_AUTHORITY_HOST` to the exact authority host you want to use
  (overrides `AZURE_CLOUD`).

## Relationship to kubelogin

kubelogin's `--login workloadidentity` path constructs an
`azidentity.WorkloadIdentityCredential` using the same inputs this sample
expects: client ID, tenant ID, federated token file path, and optional cloud
configuration. By exercising the flow directly you can validate that the
workload identity assignment and AKS delegated permissions are configured
correctly before wiring them into the proxy.
