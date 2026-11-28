# Connect GitLab to Bellu Code

Bellu Code reads your GitLab projects and groups with read-only access. It works with gitlab.com and with self-managed hosts.

## Auth methods

- **Sign in with GitLab** (device flow). You approve a code in your browser. Bellu Code requests only the `read_api` scope and renews the token with its refresh token. This method appears only when a Client ID is configured (see below).
- **Personal access token.** Paste a token you create yourself. It cannot be renewed, so reconnect when it expires.

## Permissions to grant

Grant `read_api` and nothing else. It lets Bellu Code read the authenticated user, projects and groups.

To create a personal access token, open GitLab > Preferences > Access tokens, tick only `read_api`, set an expiry and copy the token. Bellu Code checks the token's scopes and warns about any scope that can write. The `read_user`, `read_repository`, `read_registry`, `read_virtual_registry` and `read_observability` scopes count as read-only. Every request is a GET regardless of the token's scopes.

## Client ID for sign-in

Sign-in needs the public Client ID of a GitLab OAuth application with the `read_api` scope and the device flow enabled. Set it in the environment bellud runs in, for example in `~/.config/bellucode/env`:

```sh
BELLUCODE_GITLAB_CLIENT_ID=<application id>
```

The Client ID is public. No client secret is used. When the variable is unset and no Client ID is compiled in, sign-in is hidden and only the personal access token is offered. Restart bellucode after changing it.

## Troubleshooting

**Sign in with GitLab is missing.** `BELLUCODE_GITLAB_CLIENT_ID` is not set. Use a personal access token, or set the variable.

**Token is invalid, revoked or expired.** Create a new token and reconnect.

**Token lacks the required read permissions.** The token does not have `read_api`. Create a new one with that scope.

**Provider rate limit reached.** Wait and retry.

**Self-managed host.** Enter the host name in the Connect dialog. Device sign-in uses gitlab.com endpoints, so use a personal access token for self-managed hosts.
