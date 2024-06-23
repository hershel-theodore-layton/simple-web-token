/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use namespace HH\Lib\Str;

/**
 * @see https://url.spec.whatwg.org/#urlencoded-parsing
 */
function parse(string $input)[]: Token {
  $parts = Str\split($input, '&'.Token::HMACSHA256.'=', 2);
  $no_hmac_swt = $parts[0];
  $submitted_hmac = idx($parts, 1);

  return new Token(
    $no_hmac_swt,
    $submitted_hmac,
    _Private\parse_x_www_form_encoded($no_hmac_swt),
  );
}
