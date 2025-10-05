/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\_Private;

use namespace HH\Lib\Str;
use function urldecode;

/**
 * @see https://url.spec.whatwg.org/#urlencoded-parsing
 */
function parse_x_www_form_encoded(string $input)[]: vec<(string, string)> {
  $result = Str\split($input, '&');
  $output = vec[];

  foreach ($result as $bytes) {
    if ($bytes === '') {
      continue;
    }

    $equals = Str\search($bytes, '=');
    $name = Str\slice($bytes, 0, $equals) |> urldecode($$);
    $value =
      $equals is nonnull ? Str\slice($bytes, $equals + 1) |> urldecode($$) : '';
    $output[] = tuple($name, $value);
  }

  return $output;
}
