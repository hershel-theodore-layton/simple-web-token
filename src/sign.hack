/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use function urlencode;

/**
 * !!!Not spec-compliant!!! HMAC should be encoded/decoded
 *
 * @deprecated Please use sign_strict(). This function may be removed in a
 * future version to prevent tempting new users of this library. 
 */
function sign(
  vec<(string, string)> $data,
  TSecretKey $secret_key,
  ?(function(string)[_]: string) $hash_func = null,
)[ctx $hash_func]: string {
  $hash_func ??= sha256_pure<>;
  return sign_strict(
    $data,
    $secret_key,
    shape(
      'url_encoder_for_data' => urlencode<>,
      'url_encoder_for_hmac' => ($dont_encode)[] ==> $dont_encode,
    ),
    $hash_func,
  );
}
