`genuniqueid:GenerateUniqueId`
==============================

Configuration
-------------

The filter supports the following configuration options:

`sourceAttribute`
:   The SAML attribute specifying the GUID (defaults to `objectGUID`).

`targetAttribute`
:   The SAML attribute to contain the new unique id. Any existing attribute with this name is replaced. Defaults to `eduPersonUniqueId`.

`scopeAttribute`
:   The SAML attribute specifying where scope can be obtained from. If the `scopeAttribute` contains an "@", then the right-hand side of the "@" is used as the scope. Defaults to `eduPersonPrincipalName`.

Examples
--------

In its simplest form, the filter is configured like this:

    'authproc' => [
        50 => [
            'class' => 'genuniqueid:GenerateUniqueId',
        ],
    ],
