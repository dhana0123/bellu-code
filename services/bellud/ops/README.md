# bellud ops

## Connector vault master key

bellud looks for the vault master key in this order: OS keyring, systemd credential
(`$CREDENTIALS_DIRECTORY/bellucode-master-key`), key file (`BELLUCODE_MASTER_KEY_FILE`),
passphrase (`BELLUCODE_VAULT_PASSPHRASE`).

### systemd credential (preferred, systemd >= 250)

```sh
sudo services/bellud/ops/bellucode-vault-init.sh      # idempotent, never prints the key
sudo install -m 0644 services/bellud/ops/bellucode.service /etc/systemd/system/bellucode.service
sudo systemctl daemon-reload
sudo systemctl restart bellucode
```

The script writes `/etc/bellucode/master-key.cred` (0600, encrypted to the host key) and
refuses to overwrite an existing one. Back up the credential and `/var/lib/systemd/credential.secret`
together, or the vault cannot be decrypted on another host.

### Key file fallback

```sh
sudo services/bellud/ops/bellucode-vault-init.sh --key-file
echo 'BELLUCODE_MASTER_KEY_FILE=/home/ubuntu/.config/bellucode/master.key' >> ~/.config/bellucode/env
```

Then remove the `LoadCredentialEncrypted=` line from the unit. The file holds 32 raw bytes, is
owned by the service user, mode 0400, and must be outside `~/.local/share/bellucode`.

### Passphrase

Set `BELLUCODE_VAULT_PASSPHRASE` in `~/.config/bellucode/env` (mode 0600) and remove
`LoadCredentialEncrypted=` from the unit.

## Unit hardening notes

`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `UMask=0077` and `LimitCORE=0` are set.
`NoNewPrivileges` means agent shells cannot use `sudo`. `UMask=0077` makes files created by agents
owner-only. `ProtectSystem=strict` is not used because agents write anywhere under `$HOME`.
