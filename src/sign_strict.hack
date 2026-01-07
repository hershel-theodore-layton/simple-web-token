/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use function base64_encode, rawurlencode, urlencode;

/**
 * @param $encoders, if one url encoder is passed, it is used for all
 * url encoder operations. If zero are passed, urlencode() is used for data,
 * since the spec requires as such. 
 */
function sign_strict(
  vec<(string, string)> $data,
  TSecretKey $secret_key,
  shape(
    ?'base64_encoder' => Encoder,
    ?'url_encoder_for_data' => Encoder,
    ?'url_encoder_for_hmac' => Encoder,
    /*_*/
  ) $encoders = shape(),
  (function(string)[_]: string) $hash_func = sha256_pure<>,
)[ctx $hash_func]: string {
  $base64_encoder = $encoders['base64_encoder'] ?? base64_encode<>;
  $url_encoder_for_data = $encoders['url_encoder_for_data'] ??
    $encoders['url_encoder_for_hmac'] ??
    urlencode<>;
  // The raw vs non-raw difference does not matter here:
  // \random_bytes(100000) |> base64_encode($$) |> rawurlencode($$) === urlencode($$)
  // For this reason, we mirror the raw vs non-raw choice of parse_strict.
  $url_encoder_for_hmac = $encoders['url_encoder_for_hmac'] ??
    $encoders['url_encoder_for_data'] ??
    rawurlencode<>;

  $no_hmac_swt =
    _Private\serialize_x_www_form_encoded($data, $url_encoder_for_data);
  $hmac = hash_hmac($hash_func, $no_hmac_swt, $secret_key)
    |> $base64_encoder($$)
    |> $url_encoder_for_hmac($$);
  return $no_hmac_swt.'&'.Token::HMACSHA256.'='.$hmac;
}
