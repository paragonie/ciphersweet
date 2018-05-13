# Key Generation

Use `random_bytes()`. It's available in PHP 7 and higher, but a polyfill provided
by [random_compat](https://github.com/paragonie/random_compat) is loaded as a
Composer dependency, so being on PHP 5 isn't a problem.

**Just use `random_bytes()`**, like so:

```php
<?php
require 'vendor/autoload.php';

$key = random_bytes(32);
```

Then save `$key` somewhere:

* A text file
* A string entry into an existing configuration file
* A PHP script that does `return ParagonIE\ConstantTime\Hex::decode(/* your hex-encoded key here */);`

The sky's the limit, really.

Then, either use an existing [KeyProvider](https://github.com/paragonie/ciphersweet/tree/master/src/KeyProvider)
or define your own, using the [KeyProviderInterface](https://github.com/paragonie/ciphersweet/blob/master/src/Contract/KeyProviderInterface.php).

-----

That's all there is to it.

Don't do something crazy like try to use a human-memorizable password as
an encryption key without key-stretching (i.e. `sodium_crypto_pwhash()`).

This library tries to side-step common mistakes, but if you go out of
your way to do something insecure, it cannot save you from the
consequences of your choices.

When in doubt, consult a cryptographer.
