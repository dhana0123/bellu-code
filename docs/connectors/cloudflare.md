# Connect Cloudflare to Bellu Code

Bellu Code reads your Cloudflare accounts and zones with a read-only API token.

## Auth methods

- **API token.** Paste a token you create yourself. Cloudflare has no device flow. Bellu Code sends it as a bearer token to `api.cloudflare.com`.

## Permissions to grant

Create a custom token at My Profile > API Tokens > Create Token, with these read permissions:

- Account > Account Settings > Read, to list accounts
- Zone > Zone > Read, to list zones
- User > API Tokens > Read, so Bellu Code can read the token's own policy and warn about write permissions

Do not add any Edit or Write permission group. Bellu Code checks the token's policy and flags any group whose name contains Edit or Write. Every request is a GET regardless.

Scope the token's account and zone resources to what you want Bellu Code to see.

## Connect

1. Create the token as above and copy it. It is shown once.
2. In Bellu Code, choose Cloudflare and paste the token. It must have no whitespace.
3. Select the zones to include.

## Troubleshooting

**Token is not active.** The token is disabled or expired. Create a new one.

**Token is invalid, revoked or expired.** Create a new token and reconnect.

**Token lacks the required read permissions.** Add the three read permissions above.

**Write permissions warning.** Remove the Edit or Write groups the warning names, or create a new read-only token.

**Provider rate limit reached.** Wait and retry.
