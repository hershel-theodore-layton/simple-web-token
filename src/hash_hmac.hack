/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use namespace HH\Lib\Str;

/**
 * @see `this_is_the_secret_key` to tag your string as a secret key.
 */
newtype TSecretKey as string = string;

function this_is_the_secret_key(string $string)[]: TSecretKey {
  return $string;
}

/**
 * `\hash_hmac()`, but available from a pure context.
 *
 * `\hash_hmac()` has `[write_props]` contexts at the time of writing.
 * @see https://github.com/facebook/hhvm/commit/9ec4a4400535521c74ebc9db47dcdf7b9785a2bc
 *
 * Similar to `\hash_hmac()`, but it accepts a function for `$hash_func`.
 * If provided with a pure hash function, such as `SimpleWebToken\sha256_pure<>`,
 * the function becomes available from a pure context.
 * `\hash()` became pure in October of 2023, which is after the release of hhvm 4.172,
 * the latest build of hhvm at the time of writing.
 * If you are using a version of hhvm with a pure implementation of `\hash()`,
 * you can forward calls to that instead.
 *
 * @param $hash_func returns its hash as binary (not hex or base64).
 * @see `SimpleWebToken\sha256_pure<>`, `SimpleWebToken\sha256_native<>`
 */
function hash_hmac(
  (function(string)[_]: string) $hash_func,
  string $data,
  TSecretKey $key,
)[ctx $hash_func]: string {
  if (Str\length($key) > _Private\SIZE_OF_SHA_256_CHUNK) {
    $key = $hash_func($key);
  }

  if (Str\length($key) < _Private\SIZE_OF_SHA_256_CHUNK) {
    $key =
      $key.Str\repeat("\0", _Private\SIZE_OF_SHA_256_CHUNK - Str\length($key));
  }

  $inner_pad = Str\repeat("\x36", _Private\SIZE_OF_SHA_256_CHUNK);
  $outer_pad = Str\repeat("\x5c", _Private\SIZE_OF_SHA_256_CHUNK);

  return $hash_func(
    _Private\str_bitwise_xor($outer_pad, $key).
    $hash_func(_Private\str_bitwise_xor($inner_pad, $key).$data),
  );
}
