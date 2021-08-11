# PHP-JWT-Guard

[![Build Status](https://github.com/paragonie/php-jwt-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/php-jwt-guard/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/php-jwt-guard/v/stable)](https://packagist.org/packages/paragonie/php-jwt-guard)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/php-jwt-guard/v/unstable)](https://packagist.org/packages/paragonie/php-jwt-guard)
[![License](https://poser.pugx.org/paragonie/php-jwt-guard/license)](https://packagist.org/packages/paragonie/php-jwt-guard)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/php-jwt-guard.svg)](https://packagist.org/packages/paragonie/php-jwt-guard)


Protect your code from being impacted by 
[issue 351 in firebase/php-jwt](https://github.com/firebase/php-jwt/issues/351).  

## Installation

First, install this library with Composer:

```terminal
composer require paragonie/php-jwt-guard
```

And then in your PHP namespace imports, swap the namespace:

```diff
- use Firebase\JWT\JWT;
+ use ParagonIE\PhpJwtGuard\JWT;
```

You're no longer going to provide an array or ArrayAccess object
to `JWT`. You will instead need to use the provided `KeyRing` class.

```php
<?php
use ParagonIE\PhpJwtGuard\KeyRing;
use ParagonIE\PhpJwtGuard\JWT;

// Setup keyring:
$keyring = (new KeyRing())
    ->withHS256('key-id-foo', 'raw-key-data-goes-here')
    ->withHS384('key-id-bar', 'raw-key-data-goes-here-too')
    // ...
    ->withPS384('key-id-xyzzy', 'raw-key-data-goes-here-too')
    ->withPS512('key-id-thud', 'raw-key-data-goes-here-too');

// Pass it to JWT Dcode:
JWT::decode($jwt, $keyring, array($allowedAlgs));
```

### Using the KeyRing class

#### KeyRing->with($alg, $keyId, $rawKeyData)

Parameters:

1. `string` $alg - The algorithm this key is intended for
2. `string` $keyId - The `kid` header that maps to this key
3. `string` $rawKeyData - The actual key material. For asymmetric keys,
   this is usually PEM-encoded.

Returns the KeyRing object. Chainable.

### KeyRing->count()

Returns an integer.

### KeyRing->partition($alg)

Parameters:

1. `string` $alg - The algorithm this key is intended for

Returns a new KeyRing object with a subset of all supported keys.
