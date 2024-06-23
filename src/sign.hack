/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use function base64_encode;

function sign(
  vec<(string, string)> $data,
  TSecretKey $secret_key,
  (function(string)[_]: string) $hash_func = sha256_pure<>,
)[ctx $hash_func]: string {
  $no_hmac_swt = _Private\serialize_x_www_form_encoded($data);
  $hmac = hash_hmac($hash_func, $no_hmac_swt, $secret_key) |> base64_encode($$);
  return $no_hmac_swt.'&'.Token::HMACSHA256.'='.$hmac;
}
