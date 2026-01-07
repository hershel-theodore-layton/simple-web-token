/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use function urldecode;

/**
 * !!!Not spec-complaint!!! hmac should be encoded/decoded
 *
 * @deprecated Please use parse_strict(). This function may be removed in a
 * future version to prevent tempting new users of this library. 
 */
function parse(string $input)[]: Token {
  return parse_strict($input, shape(
    'url_decoder_for_data' => urldecode<>,
    'url_decoder_for_hmac' => $dont_decode ==> $dont_decode,
  ));
}
