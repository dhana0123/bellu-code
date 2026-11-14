# Connect Microsoft Azure to Bellu Code

Bellu Code reads your Azure subscriptions with a read-only identity.

## Auth methods

- **Sign in with Microsoft** (device flow). You approve a code at microsoft.com/devicelogin. Bellu Code requests the delegated scope `https://management.azure.com/user_impersonation` plus `offline_access` so it can renew the token. This method appears only when a Client ID is configured (see below).
- **Service principal.** Not available yet. The method is listed but disabled, because Bellu Code cannot yet exchange a pasted client secret for a token. Use Sign in with Microsoft.

## Permissions to grant

Sign-in acts as you, so the signed-in user needs these built-in Azure roles on each subscription to include:

- `Reader` to read subscriptions and resources
- `Security Reader` to read security posture

Bellu Code reads the subscription list, role assignments and the signed-in identity's permissions. It warns if the identity holds roles that can write, such as Contributor or Owner. Use a user with only the two read roles. Every request is a GET.

## Client ID for sign-in

Sign-in needs the Application (client) ID of a Microsoft Entra app registration that allows public client flows and has the delegated Azure Service Management `user_impersonation` permission. Set it in the environment bellud runs in, for example in `~/.config/bellucode/env`:

```sh
BELLUCODE_AZURE_CLIENT_ID=<application (client) id>
```

The Client ID is public. No client secret is used. When it is unset and none is compiled in, sign-in is hidden. Restart bellucode after changing it.

## Troubleshooting

**Sign in with Microsoft is missing.** `BELLUCODE_AZURE_CLIENT_ID` is not set. The service principal method cannot replace it yet.

**Token is invalid, revoked or expired.** Sign in again.

**Token lacks the required read permissions.** The user has no role on the subscription. Assign `Reader` and `Security Reader`.

**No subscriptions listed.** The user has no role on any subscription, or the tenant differs from the one you signed in to.

**Provider rate limit reached.** Wait and retry.
