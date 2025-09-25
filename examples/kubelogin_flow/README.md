# AKS delegated token sample using the kubelogin public client

This sample demonstrates how to authenticate a user with Microsoft Entra ID
using the same public client application (`80faf920-1908-4b52-b5ef-a8e7bedfc67a`)
that the `kubelogin` project relies on. After the user signs in, the script
requests a delegated token for the Azure Kubernetes Service (AKS) resource
application (`6dae42f8-4368-4678-94ff-3960e28e3630`) using the `/.default`
scope, matching the behavior of kubelogin when it obtains user tokens for AKS.

## Prerequisites

* Python 3.10+
* The dependencies listed in the repository’s `requirements.txt` (install with
  `pip install -r requirements.txt`)
* An Azure tenant where the AKS resource application is available (for Azure
  public cloud tenants this is provided by Microsoft)

## Running the sample

1. Export your tenant ID so the script knows which authority to target:

   ```bash
   export AZURE_TENANT_ID=<tenant-guid>
   ```

   Optional environment variables:

   | Variable | Description |
   | --- | --- |
   | `AKS_SERVER_APP_ID` | Override the AKS resource application ID (defaults to the Microsoft AKS server app). |
   | `AZURE_CLOUD` | Set to `AzureUSGovernment` or `AzureChinaCloud` when running in those sovereign clouds. |
   | `MSAL_CACHE_PATH` | Path to persist the MSAL token cache (default `~/.cache/aks_public_client_token.json`). |

2. Run the device-code login script:

   ```bash
   python examples/kubelogin_flow/aks_public_client.py
   ```

   On first run MSAL will present a device code and URL. Open the URL, enter the
   code, and sign in with a user that has been granted the AKS delegated
   permission. After consent is recorded, the script prints a confirmation along
   with a truncated copy of the issued access token.

3. Subsequent executions reuse the cached authentication record and only fall
   back to device-code if the cached token and refresh token have expired or the
   user revoked consent.

## Notes

* The sample mirrors kubelogin’s behavior by always requesting the resource’s
  `/.default` scope. Ensure your tenant grants the desired delegated permission
  (for example `user_impersonation` or `User.Read`) to the public client.
* If you need to examine the full access token, remove the truncation logic in
  `aks_public_client.py`, but take care when handling raw tokens in logs.
