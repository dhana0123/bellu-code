# Connect Bitbucket to Bellu Code

Bellu Code reads your Bitbucket Cloud workspaces and repositories with read-only access.

## Auth methods

- **Email and Atlassian API token.** Bitbucket Cloud has no device flow, so there is no sign-in button. You paste your account email and an Atlassian API token. Bellu Code sends them as HTTP Basic auth to `api.bitbucket.org`.

## Permissions to grant

Create the token under Atlassian account settings > Security > API tokens, choosing a token with scopes. Grant read scopes only:

- `read:user:bitbucket` to read the account
- `read:workspace:bitbucket` to list workspaces
- `read:repository:bitbucket` to list repositories

Do not grant any scope with `write`, `admin` or `delete` in it. Bellu Code reads the granted scopes from the API response and warns about any such scope. Every request is a GET regardless.

## Connect

1. In Bellu Code, choose Bitbucket.
2. Enter the account email and paste the API token. The token must not contain whitespace.
3. Select the workspaces to include.

API tokens expire. Reconnect with a new token when it does.

## Troubleshooting

**Email or API token is invalid, revoked or expired.** Check the email matches the Atlassian account that owns the token, or create a new token.

**Token lacks the required read scopes.** Add the three read scopes above to a new token.

**Email must be a valid address.** Enter the email, not the Bitbucket username.

**Provider rate limit reached.** Wait and retry.
