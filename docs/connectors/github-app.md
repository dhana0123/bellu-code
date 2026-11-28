# GitHub App for Sign in with GitHub

Bellu Code connects to GitHub through one public GitHub App, "Bellu Code", using the device authorization flow. The device flow needs only the App's Client ID. It needs no callback URL and no client secret.

## Status

The project owner supplies the real Client ID after registering the App. Until then the constant `ClientID` in `services/bellud/internal/connectors/github/clientid.go` is empty, and sign-in stays hidden while it is empty. The Connect dialog then offers only the fine-grained personal access token under Advanced.

## Registering the App

Register the App on github.com under Settings > Developer settings > GitHub Apps > New GitHub App. Forks that use their own App follow the same checklist.

- [ ] Name: `Bellu Code`
- [ ] Device flow: enabled ("Enable Device Flow")
- [ ] User token expiration: disabled ("Expire user authorization tokens" unchecked)
- [ ] Callback URL: left empty
- [ ] Webhook: inactive ("Active" unchecked)
- [ ] Installation: allowed on any account (public)
- [ ] Repository permission, Metadata: read-only
- [ ] Repository permission, Contents: read-only
- [ ] Repository permission, Pull requests: read-only
- [ ] Repository permission, Issues: read-only
- [ ] Repository permission, Actions: read-only
- [ ] Repository permission, Dependabot alerts: read-only
- [ ] Repository permission, Code scanning alerts: read-only
- [ ] Repository permission, Secret scanning alerts: read-only

Grant no other permissions. After saving, copy the Client ID from the App's settings page.

## Client ID and Client Secret

The Client ID is a public identifier. It is safe to ship in source, and it is the only App value in the repository.

The Client Secret is not safe to ship. It is generated only when a documented feature requires it. The device flow does not. Only the project owner holds it, and it is never committed to the repository. Bellu Code ignores a client secret supplied through configuration, an environment variable or a request.

## Forks

A fork that registers its own App sets `BELLUCODE_GITHUB_CLIENT_ID` to that App's Client ID in the environment bellud runs in, for example in `~/.config/bellucode/env`. If the fork's App has a different slug, also set `BELLUCODE_GITHUB_APP_SLUG`. The slug builds the "Install Bellu Code on GitHub" link.

When `BELLUCODE_GITHUB_CLIENT_ID` is unset or empty, bellud uses the shipped Client ID.

## Token expiration

The App is registered with user token expiration disabled. Refreshing an expiring token requires the Client Secret, which Bellu Code does not have, so tokens that expire cannot be renewed. If a token does carry an expiry, the connection ends in Expired and the user reconnects through Sign in with GitHub.

## Keeping authorization across restarts

Without a vault master key, bellud holds credentials only in memory, and GitHub authorization is lost when bellud restarts. The Connect dialog shows a notice in that case, and connections left without a credential show as Expired until the user reconnects.

Set up the master key to persist authorization. The exact steps are in [`services/bellud/ops/README.md`](../../services/bellud/ops/README.md), and the script is `services/bellud/ops/bellucode-vault-init.sh`. In short, run the script as root:

```sh
sudo services/bellud/ops/bellucode-vault-init.sh             # systemd-creds, needs systemd >= 250
sudo services/bellud/ops/bellucode-vault-init.sh --key-file  # fallback key file
```

The default mode writes an encrypted credential to `/etc/bellucode/master-key.cred`, which the unit loads with `LoadCredentialEncrypted=`. The `--key-file` mode writes `~/.config/bellucode/master.key`. You then add `BELLUCODE_MASTER_KEY_FILE` to `~/.config/bellucode/env` and remove the `LoadCredentialEncrypted=` line from the unit. Restart bellucode afterwards. The script never overwrites an existing key and never prints it. As an alternative, `BELLUCODE_VAULT_PASSPHRASE` also works; see the ops README.
