/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\_Private;

use function urlencode;

/**
 * @see https://url.spec.whatwg.org/#urlencoded-serializing
 */
function serialize_x_www_form_encoded(vec<(string, string)> $pairs)[]: string {
  $output = '';

  foreach ($pairs as list($key, $value)) {
    $pair = urlencode($key).'='.urlencode($value);

    if ($output === '') {
      $output = $pair;
    } else {
      $output .= '&'.$pair;
    }
  }

  return $output;
}
