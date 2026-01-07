/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\_Private;

use namespace HTL\SimpleWebToken;

/**
 * @see https://url.spec.whatwg.org/#urlencoded-serializing
 */
function serialize_x_www_form_encoded(
  vec<(string, string)> $pairs,
  SimpleWebToken\Encoder $url_encoder,
)[]: string {
  $output = '';

  foreach ($pairs as list($key, $value)) {
    $pair = $url_encoder($key).'='.$url_encoder($value);

    if ($output === '') {
      $output = $pair;
    } else {
      $output .= '&'.$pair;
    }
  }

  return $output;
}
