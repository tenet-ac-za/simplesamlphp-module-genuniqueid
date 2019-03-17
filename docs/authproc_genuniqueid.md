`genuniqueid:GenerateUniqueId`
==============================

Configuration
-------------

The filter supports the following configuration options:

`sourceAttribute`
:   The SAML attribute specifying the GUID (default depends on `encoding` --- see the value in brackets below).

`targetAttribute`
:   The SAML attribute to contain the new unique id. Any existing attribute with this name is replaced. Defaults to `eduPersonUniqueId`.

`scopeAttribute`
:   The SAML attribute specifying where scope can be obtained from. If the `scopeAttribute` contains an "@", then the right-hand side of the "@" is used as the scope. Defaults to `eduPersonPrincipalName`.

`encoding`
:   The encoding of the attribute. Must be one of the following (defaults to `microsoft`):
> * `microsoft` - Microsoft's base64 encoded, mixed-endian binary format. [`objectGUID`].
> * `edirectory` - Base64 encoded, big-endian format. [`guid`].
> * `openldap` - String UUID representation. [`entryUUID`].

`privacy`
:   Whether to hash the resulting value to preserve privacy (boolean, defaults to `false`).

Examples
--------

In its simplest form, the filter is configured like this:

    'authproc' => [
        50 => [
            'class' => 'genuniqueid:GenerateUniqueId',
        ],
    ],

To specify a specific encoding format, such as OpenLDAP's entryUUID format, do this:

    'authproc' => [
        50 => [
            'class' => 'genuniqueid:GenerateUniqueId',
            'encoding' => 'openldap',
        ],
    ],

To specify different attribute names, do this:

    'authproc' => [
        50 => [
            'class' => 'genuniqueid:GenerateUniqueId',
            'encoding' => 'openldap',
            'sourceAttribute' => 'mySourceAttribute',
            'targetAttribute' => 'myTargetAttribute',
            'scopeAttribute' => 'myScopeAttribute',
        ],
    ],

Encoding
--------

GUID/UUIDs are represented in a canonical textual representation displayed as hexadecimal in 5 groups separated by hyphens, in the form 8-4-4-4-12. However, the [schema for `eduPersonUniqueId`](https://wiki.refeds.org/pages/viewpage.action?pageId=38895708#eduPerson(201602)-eduPersonUniqueId) requires a uniqueID "contain only alphanumeric characters (a-z, A-Z, 0-9)". Thus this module encodes GUIDs as uniqueIDs in lower case with no hyphens.

### Microsoft

Microsoft's ActiveDirectory records the objectGUID in a [mixed-endian format](https://en.wikipedia.org/wiki/Universally_unique_identifier#Encoding). With this encoding, an LDAP attribute of:
```
objectGUID:: gOH1SbeT2hGsbgAH6UDz7g==
```
corresponds to a decoded GUID of `49f5e180-93b7-11da-ac6e-0007e940f3ee`.

### e-Directory

It is hard to find documentation of how MicroFocus encode GUIDs in e-Directory, but it is assumed they are big-endian. This an LDAP attribute of:
```
guid:: gOH1SbeT2hGsbgAH6UDz7g==
```
corresponds to a decoded GUID of `80e1f549-b793-da11-ac6e-0007e940f3ee`.
