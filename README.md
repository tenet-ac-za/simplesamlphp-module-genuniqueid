genuniqueid:GenerateUniqueId
============================
![Build Status](https://github.com/tenet-ac-za/simplesamlphp-module-genuniqueid/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://codecov.io/gh/tenet-ac-za/simplesamlphp-module-genuniqueid/branch/master/graph/badge.svg)](https://codecov.io/gh/tenet-ac-za/simplesamlphp-module-genuniqueid)

Generate an eduPersonUniqueId attribute from various LDAP implementations' objectGUID

Installation
------------

Once you have installed SimpleSAMLphp, installing this module is
very simple.  Just execute the following command in the root of your
SimpleSAMLphp installation:

```
composer.phar require safire-ac-za/simplesamlphp-module-genuniqueid:dev-master
```

where `dev-master` instructs Composer to install the `master` (**development**)
branch from the Git repository. See the
[releases](https://github.com/tenet-ac-za/simplesamlphp-module-genuniqueid/releases)
available if you want to use a stable version of the module.

Documentation
-------------

See [docs/authproc_genuniqueid.md](https://github.com/tenet-ac-za/simplesamlphp-module-genuniqueid/blob/master/docs/authproc_genuniqueid.md).
