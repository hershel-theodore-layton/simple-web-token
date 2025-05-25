# simple-web-token

_An implementation of the Simple Web Token specification._

### Usage

```HACK
// This example assumes you have some `$your_key_store`,
// which maps key names to keys.

$serialized = SimpleWebToken\sign(
  vec[
    tuple('com.example.user_id', '4'),
    tuple(SimpleWebToken\Token::EXPIRES_ON, (string)(\time() + 300)),
    tuple('com.example.secret_key_used', '#1')
  ],
  SimpleWebToken\this_is_the_secret_key($your_key_store->load('#1')),
);

$token = SimpleWebToken\parse($serialized);

$key = $your_key_store->loadKey(
  $token->getUniqueKeys() |> idx($$, 'com.example.secret_key_used', 'default')
);

$state = $token->validate($key, \time());

switch ($state) {
  case SimpleWebToken\Validity::VALID:
  case SimpleWebToken\Validity::EXPIRED:
  case SimpleWebToken\Validity::INVALID:
}

// Or the shorthand
$token->isOkay($key, \time()); // This returns `true` for `::VALID` only.
```

### Performance vs. purity

The native functions `\hash()` and `\hash_hmac()` are not pure in hhvm version 4.172
and below (the most recent version released to date). `\hash()` has been made pure
in October 2023. This repository includes `SimpleWebToken\sha256_pure()` as
a replacement for `\hash()`, which is pure.

When running in repo auth mode, the jit will kick in and make the performance of
this polyfill about 20% of the native `\hash()` function. The performance deficit
is greater before the jit has optimized it, especially when not running in repo
auth mode. If you have a very high traffic to your site and CPU cycles are scarce,
you will definitely feel the hit of the unoptimized bytecodes shuffling bytes
around. You may opt to use `SimpleWebToken\sha256_native()` to regain all
performance, at the cost of requiring `[defaults]`.

If you are running a build of hhvm@next at or after [this commit](https://github.com/facebook/hhvm/commit/9ec4a4400535521c74ebc9db47dcdf7b9785a2bc)
from October 2023. You can pass a native wrapper with a pure context.

The latest release Oxygen is able to run on hhvm@next. This version of
`sha256_native` `return hash('sha256', $data, true);` is now pure.
You can create a pure version of `sha256_native` and hash your tokens ever
so slightly faster.

### License

This code is licensed under the [MIT License](./LICENSE), but note,
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
Both licenses are public domain equivalent and do not require attribution.
Thank you Amosnier, porting it was a pleasant experience.

I believe to have met the requirements imposed on me by the third-party licenses.
If you spot a violation of any third-party licenses in under this Github namespace,
you may notify me by filing a Github Issue on the affected projects.
