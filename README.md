# LDAP client

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-ldap
```

### RHEL

```
yum install halon-extras-ldap
```

## Exported classes

These classes needs to be [imported](https://docs.halon.io/hsl/structures.html#import) from the `extras://ldap` module path.

### LDAP(uri)
The LDAP class is a OpenLDAP wrapper class.

**Params**

- uri `string` - The URI should be in the format of `ldap://` or `ldaps://`. Multiple hosts may be given separated by space.

**Returns**: class object

```
$ldap = LDAP("ldap://ldap.forumsys.com");
$ldap->bind("uid=tesla,dc=example,dc=com", "password");
$x = $ldap->search("dc=example,dc=com");
while ($x and $entry = $x->next())
    echo $entry;
```

#### setoption(name, value)
Set LDAP connection options. On error `none` is returned.

**Params**

- name `string` - the option name
- value `any` - the option value

**Returns**: this

**Return type**: `LDAP` or `none`

```
if (!$ldap->setoption("network_timeout", 5))
    echo LDAP::err2string($ldap->errno());
```

The following options are available

| Name              | Type    | Default | Description                                    |
| ----------------- | ------- | ------- | ---------------------------------------------- |
| protocol_version  | number  | `3`     |                                                |
| referrals         | boolean | `false` |                                                |
| network_timeout   | number  | `0`     | No timeout                                     |
| timeout           | number  | `0`     | No timeout (in seconds)                        |
| timelimit         | number  | `0`     | No timelimit (in seconds)                      |
| tls_verify_peer   | boolean | `true`  | Verify peer certificate                        |
| tls_default_ca    | boolean | `false` | Load additional TLS certificates (ca_root_nss) |

#### getoption(name)
Get LDAP connection options. On error `none` is returned.

**Params**

- name `string` - the option name

**Returns**: result

**Return type**: `any` or `none`

The following options are available

| Name               | Type    | Description                           |
| ------------------ | ------- | ------------------------------------- |
| diagnostic_message | string  | Gets the latest session error message |

#### starttls()
Issue STARTTLS on LDAP connection. On error `none` is returned.

**Returns**: this

**Return type**: `LDAP` or `none`

#### bind([dn [, cred]])
Bind the LDAP connection. For anonymous bind, do not specify the credentials. On error `none` is returned.

**Params**

- dn `string` - The username DN
- cred `string` - The password credentials

**Returns**: this

**Return type**: `LDAP` or `none`

#### search(basedn [, options])
Search LDAP connection in the current base and subtree. On error `none` is returned.

**Params**

- basedn `string` - Base DN
- options `array` - an options array

The following options are available in the options array.

- scope `string` - The search scope, available scopes are `sub` (subtree), `one` (onelevel) and `base`. The default is `sub`.
- filter `string` - The search filter. The default is `(objectclass=*)`.
- attributes `array` - Array of attributes to fetch. The default is to fetch all.

**Returns**: A LDAP result class

**Return type**: `LDAPResult` or `none`

#### unbind()
Unbind the LDAP connection. On error `none` is returned.

**Returns**: this

**Return type**: `LDAP` or `none`

#### errno()
Get the latest errno returned from the underlying OpenLDAP API.

**Returns**: errno

**Return type**: `number`

#### getpeerx509()
Get the peer certificate (X.509) as a `X509` instance. On error `none` is returned.

**Returns**: The peer certificate

**Return type**: `X509` or `none`

#### static err2string(errno)
Get a descriptive error message, uses OpenLDAP’s `ldap_err2string()`.

**Params**

- errno `number` - A errno (obtained from LDAP’s errno())

**Returns**: An error string

**Return type**: `string`

```
if (!$ldap->bind())
    echo LDAP::err2string($ldap->errno());
```

#### static filter_escape(value)
LDAP escape values to be used in LDAP filters.

**Params**

- value `string` - An unescaped string

**Returns**: An escaped string

**Return type**: `string`

```
$result = $ldap->search("dc=example,dc=com", ["filter" => "(cn=" . LDAP::filter_escape($cn) . ")"]);
```

#### static str2dn(str)
Parses the string representation of a distinguished name str into its components, returning an array of tupels. On error `none` is returned.

**Params**

- str `string` - String representation of a DN

**Returns**: Array of tupels

**Return type**: `array` or `none`

```
echo LDAP::str2dn("cn=admin,dc=example,dc=org");
// [0=>[0=>"cn",1=>"admin"],1=>[0=>"dc",1=>"example"],2=>[0=>"dc",1=>"org"]]
```

#### static dn2str(dn)
Performs the inverse operation of `str2dn()`, returning a string representation of dn with the necessary escaping. On error `none` is returned.

**Params**

- dn `array` - Array of tupels

**Returns**: String representation of the DN

**Return type**: `string` or `none`

### LDAPResult
A LDAP result iterable object which holds the result from an LDAP search.

#### next()
Return the next result. If there are no more results `false` is returned, and on error `none` is returned.

**Returns**: entry data

**Return type**: `array` or `none`

```
$result = $ldap->search("dc=example,dc=com");
if ($result)
  while ($entry = $result->next())
    echo $entry;
```