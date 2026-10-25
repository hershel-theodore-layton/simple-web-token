# simple-web-token

_An implementation of the Simple Web Token specification._

### Usage

`Token::validate()` returns `Validity::VALID`, `EXPIRED`, or `INVALID`;
`isOkay()` is true only for `VALID`.

`VALID` means the signature is correct, reserved claims have acceptable
multiplicity, and `ExpiresOn` is valid and unexpired **when present**. It does
not check `Issuer` or `Audience` values, or require expiry. Applications must
apply those policies themselves, especially when services share signing keys.

This example requires the expected issuer, audience, and expiry. Its key store
is an application-controlled allowlist; use secret storage for the real keys.

```HACK
namespace Example;

use namespace HTL\SimpleWebToken;

function accepted_user_id(
  string $serialized,
  dict<string, SimpleWebToken\TSecretKey> $allowed_keys,
  int $now,
): string {
  $token = SimpleWebToken\parse_strict($serialized);
  $claims = $token->getUniqueKeys();

  // Claims are untrusted here. The identifier may only select an allowed key.
  // Missing, repeated, or unknown identifiers are rejected, without a fallback.
  $key_id = $claims['com.example.secret_key_used'] ?? null;
  if ($key_id is null || $key_id === '') {
    throw new \InvalidArgumentException('Missing or repeated key identifier');
  }
  $key = $allowed_keys[$key_id] ?? null;
  if ($key is null || !$token->isOkay($key, $now)) {
    throw new \InvalidArgumentException('Invalid token or unknown key');
  }

  if (
    ($claims[SimpleWebToken\Token::ISSUER] ?? '') !== 'example-issuer' ||
    ($claims[SimpleWebToken\Token::AUDIENCE] ?? '') !== 'example-service' ||
    !\array_key_exists(SimpleWebToken\Token::EXPIRES_ON, $claims)
  ) {
    throw new \InvalidArgumentException('Token does not satisfy application policy');
  }

  $user_id = $claims['com.example.user_id'] ?? null;
  if ($user_id is null) {
    throw new \InvalidArgumentException('Missing user ID');
  }
  return $user_id;
}

<<__EntryPoint>>
function example(): void {
  // Issuance is separate from accepting a received token.
  $allowed_keys = dict[
    '#1' => SimpleWebToken\this_is_the_secret_key('replace-with-a-stored-secret'),
  ];
  $now = \time();
  $serialized = SimpleWebToken\sign_strict(
    vec[
      tuple(SimpleWebToken\Token::ISSUER, 'example-issuer'),
      tuple(SimpleWebToken\Token::AUDIENCE, 'example-service'),
      tuple(SimpleWebToken\Token::EXPIRES_ON, (string)($now + 300)),
      tuple('com.example.secret_key_used', '#1'),
      tuple('com.example.user_id', '4'),
    ],
    $allowed_keys['#1'],
  );
  echo accepted_user_id($serialized, $allowed_keys, $now);
}
```

Malformed serialized input can make `parse_strict()` throw. Handle parsing and
policy failures at the application's authentication boundary.

`Issuer`, `Audience`, and `ExpiresOn` may occur at most once. Claims named
`HMACSHA256` are rejected by validation. Keep application-controlled reserved
claims separate from user-supplied claims. Signing serializes and signs its
input; it does not validate reserved claims. For example, signing a claim named
`HMACSHA256` produces a token that validation rejects.

### Performance vs. purity

The native functions `\hash()` and `\hash_hmac()` are not pure in HHVM version 4.172
and below (the most recent version released to date). `\hash()` was made pure
in October 2023. This repository includes `SimpleWebToken\sha256_pure()` as
a replacement for `\hash()`, which is pure.

When running in repo auth mode, the JIT will kick in and make the performance of
this polyfill about 20% of the native `\hash()` function. The performance deficit
is greater before the JIT has optimized it, especially when not running in repo
auth mode. If you have very high traffic on your site and CPU cycles are scarce,
you will definitely feel the hit of the unoptimized bytecodes shuffling bytes
around. You may opt to use `SimpleWebToken\sha256_native()` to regain all
performance, at the cost of requiring `[defaults]`.

If you are running a build of HHVM@next at or after [this commit](https://github.com/facebook/hhvm/commit/9ec4a4400535521c74ebc9db47dcdf7b9785a2bc)
from October 2023, you can pass a native wrapper with a pure context.

The latest release, Oxygen, is able to run on HHVM@next. This version of
`sha256_native` using `return hash('sha256', $data, true);` is now pure.
You can create a pure version of `sha256_native` and hash your tokens ever
so slightly faster.

### License

This code is licensed under the [MIT License](./LICENSE), but note that
this code implements the Simple Web Token specification.

The Simple Web Token specification version 0.9.5.1, which can be found [here](<https://learn.microsoft.com/en-us/previous-versions/azure/azure-services/hh781551(v=azure.100)?redirectedfrom=MSDN>),
is licensed under the [Open Web Foundation Agreement Version 0.9](https://www.openwebfoundation.org/the-agreements/the-owf-0-9-agreements-necessary-claims/open-web-foundation-agreement-0-9).
This license is permissive, as long as you do not take
non-defensive patent legal action against implementers of the specification.
This also applies to this implementation (and implementer).

### Acknowledgments

The Simple Web Token specification has been authored by:

- Dick Hardt (dick.hardt@microsoft.com), Editor
- Yaron Goland (yarong@microsoft.com)

The implementation of SHA-256 in Hack was heavily based on amosnier's C implementation.
This Hack implementation can be found [here](https://github.com/hershel-theodore-layton/simple-web-token/blob/master/src/_Private/sha256.c.hack).
The implementation in C can be found [here](https://github.com/amosnier/sha-2/tree/b29613850d6e54e7159197ef42c7d22d012b6367).
The C code is licensed under `The Unlicense` or `BSD-0-Clause` at your option.
Both licenses are public-domain equivalents and do not require attribution.
Thank you, Amosnier. Porting it was a pleasant experience.

I believe I have met the requirements imposed on me by the third-party licenses.
If you spot a violation of any third-party licenses under this GitHub namespace,
you may notify me by filing a GitHub issue on the affected projects.
