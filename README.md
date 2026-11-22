# azx

Token vault and CLI for authorized Entra ID and Azure work.

## Install

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Authenticate with a client secret

Use an application ID, secret, tenant, and resource.

```bash
azx auth app -c <client-id> -p <secret> -t <tenant> -r msgraph
```

## Authenticate with a certificate

Use a PFX or PEM client certificate for cloud certificate-based authentication.

```bash
azx auth cba --pfx cert.pfx -t contoso.onmicrosoft.com
azx auth cba --pfx cert.pfx -t contoso.onmicrosoft.com -c <client-id> --redirect-uri https://login.microsoftonline.com/common/oauth2/nativeclient
```

## Authenticate with Seamless SSO

### Use the current user's Kerberos ticket

Pass the current user's TGT cache and the domain controller used to request the Seamless SSO service ticket.

```bash
azx auth seamless -t contoso.com -d contoso.local --dc dc01.contoso.local --tgt /path/to/krb5cc
```

### Authenticate with a user NTLM hash

Use the user's NTLM hash for domain authentication.

```bash
azx auth seamless -t contoso.com -d contoso.local --dc dc01.contoso.local -u user --ntlm <nthash>
```

### Forge a service ticket with the AZUREADSSOACC AES key

Use the AZUREADSSOACC AES key and the target user's SID.

```bash
azx auth seamless -t contoso.com --adssoacc-aes <aes-key> --user-sid S-1-5-21-1111111111-2222222222-3333333333-1101
```

## Manage tokens

Tokens are stored in `~/.azxtokens` as plaintext JSON with mode `0600`. Set `AZX_TOKENS_DIR` to change the location.

```bash
azx token list
azx token current
azx token select
azx token show <name>
azx token refresh [name]
azx token import <file>
azx token export <name> --tokenfile <path>
```

## Use a token

The active token is used by default. Pass `--token` to use a specific one.

```bash
azx whoami
azx --token <name> whoami
```

## Query users and groups

Use object IDs or UPNs where accepted.

```bash
azx user get user@contoso.com
azx user groups user@contoso.com
azx group list
azx group members <group-id>
azx group add-member <group-id> --member <user-id>
```

## Manage authentication methods and TAPs

List, add, or remove authentication methods, or create a Temporary Access Pass.

```bash
azx authmethod list user@contoso.com
azx authmethod add user@contoso.com --type phone --phone-number +15550100
azx tap create user@contoso.com --lifetime 60
azx tap list user@contoso.com
```

## Manage roles

Manage directory roles and application permissions.

```bash
azx role list
azx role list-members <role-id>
azx role assign <principal-id> --role <role-template-id>
```

## Work with Azure

List subscriptions, manage Azure RBAC, or grant tenant-root User Access Administrator.

```bash
azx azure subscriptions
azx azure role list --scope /subscriptions/<subscription-id>
azx azure uaa assign
```

## Work with applications and service principals

Manage application registrations, secrets, and service principals.

```bash
azx app list
azx app create my-app
azx app secret add <client-id> --secret-name ci --lifetime 30
azx sp list
azx sp get <client-id>
azx sp create <client-id>
```

## Work with enterprise apps and Intune

Manage enterprise application role assignments and list Intune inventory.

```bash
azx myapps list
azx myapps assign <user-id> --app <app-id> --role <role>
azx intune devices
azx intune apps
```

## Send raw API requests

Send GET requests to Microsoft Graph or Azure Resource Manager.

```bash
azx graph get /users
azx graph get /me
azx arm get '/subscriptions?api-version=2022-12-01'
```

## Common options

Use a specific token, save the transcript, proxy requests, or show HTTP debug output.

```bash
azx --token <name> whoami
azx -o output.txt graph get /me
azx --proxy http://127.0.0.1:8080 graph get /me
azx --debug graph get /me
```

`--proxy` disables TLS verification. `--debug` output is not redacted.
