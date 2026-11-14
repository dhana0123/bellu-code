# Connect Google Cloud to Bellu Code

Bellu Code reads your Google Cloud projects with a read-only service account. You create the account once, then paste its key.

## Auth methods

- **Service account key (JSON).** Bellu Code exchanges the key for short-lived access tokens at `oauth2.googleapis.com`. There is no sign-in option, because no public client ID is available.

## Permissions to grant

Grant the service account two predefined roles on each project (or on the folder or organization above them):

- `Viewer` (`roles/viewer`) to read projects and resources
- `Security Reviewer` (`roles/iam.securityReviewer`) to read IAM policies and security settings

Bellu Code lists projects with the Resource Manager API and tests a fixed set of write permissions on the first active project. It warns about any write permission the account holds. It only ever sends the permission probe as a POST. Every other request is a GET.

## Connect

1. In the Google Cloud console, open IAM & Admin > Service Accounts and create an account.
2. Grant it the two roles above.
3. Open the account's Keys tab, choose Add key > Create new key > JSON, and download the file.
4. In Bellu Code, choose Google Cloud and paste the JSON. It must have `type` set to `service_account`, plus `client_email` and `private_key`.
5. Select the projects to include.

The key is long-lived. Delete it in the console when you disconnect.

## Troubleshooting

**Service account key is invalid or revoked.** The key was deleted or disabled. Create a new one.

**Service account lacks permission to list projects.** Grant `Viewer` and enable the Cloud Resource Manager API on the key's project.

**Field `client_email` or `private_key` is required.** You pasted something other than a service account key file.

**Provider rate limit reached.** Wait and retry.
