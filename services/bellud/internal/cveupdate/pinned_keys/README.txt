Pinned_Keys for CVE snapshot verification (Requirement 19.10).

Each *.pub file holds one Ed25519 public key in the format written by
`bellu-intel keygen` (base64, one line). Every file is embedded in the binary.
Several keys may be present during a rotation. With no key, every update is
rejected. Add the release signing key here before shipping.
