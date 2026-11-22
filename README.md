# azx

Tool for performing common actions for Entra and on-prem pivoting.

## Install

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Authenticate

**As an application**

Use an application ID, secret, tenant, and resource.

```bash
azx auth app -c <client-id> -p <secret> -t <tenant> -r msgraph
```

**Using a certificate**

Use a PFX or PEM client certificate for cloud certificate-based authentication.

```bash
azx auth cba --pfx cert.pfx -t contoso.onmicrosoft.com
azx auth cba --pfx cert.pfx -t contoso.onmicrosoft.com -c <client-id> --redirect-uri https://login.microsoftonline.com/common/oauth2/nativeclient
```

**With seamless / desktop sso**

Use a Kerberos ticket.

```bash
azx auth seamless -t contoso.com -d contoso.local --dc dc01.contoso.local --tgt /path/to/krb5cc
```

Use an NTLM hash for domain authentication.

```bash
azx auth seamless -t contoso.com -d contoso.local --dc dc01.contoso.local -u user --ntlm <nthash>
```

Use the AZUREADSSOACC AES key and the target user's SID.

```bash
azx auth seamless -t contoso.com --adssoacc-aes <aes-key> --user-sid S-1-5-21-1111111111-2222222222-3333333333-1101
```

**With tokens you've already collected**

```bash
azx token import --access-token <at> --refresh-token <rt>

# or 

azx token import <file>
```

## Manage tokens

Tokens are stored in `~/.azxtokens` as plaintext JSON.

**Setting an active token**

Before you can perform any authenticated functions you must set an active token.

```bash
# will launch a TUI selector. 
azx token select 
```

**Refreshing tokens**

Tokens that expire can be refreshed if a refresh token exists for the client.

```bash
# refreshing the active token
azx token refresh

# refreshing a stored token
azx token refresh [NAME]
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

## Manage authentication methods

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
# use global administrator privileges to assign user access administrator, gaining access to azure resource manager.
azx azure uaa assign

# list subscriptions.

azx azure subscriptions

# list roles scoped to specific resource.

azx azure role list --scope /subscriptions/<subscription-id>
```

## Work with applications and service principals

Manage application registrations, secrets, and service principals.

```bash
azx app list
azx app create my-app
azx app secret add <client-id> --secret-name <mysecret>
azx sp list
azx sp get <client-id>
azx sp create <client-id>
```

## Work with enterprise apps

Manage enterprise application role assignments.

```bash
azx myapps list
azx myapps assign <user-id> --app <app-id> --role <role>
```

## Send raw API requests

Send GET requests to Microsoft Graph or Azure Resource Manager.

```bash
azx graph get /users
azx graph get /me
azx arm get '/subscriptions?api-version=2022-12-01'
```
