/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\_Private;

use namespace HH\Lib\Str;
use function chr, ord;

/**
 * This function was added in the `HH` namespace with the release of hhvm 4.163,
 * but it was not added to the hhi files. Implementing it from scratch to maintain
 * support for older hhvm versions.
 */
function str_bitwise_xor(string $a, string $b)[]: string {
  $length = Str\length($a);

  invariant(
    Str\length($b) === $length,
    'Xor candidates must have equal length, got %d & %d',
    $length,
    Str\length($b),
  );

  for ($i = 0; $i < $length; ++$i) {
    $a[$i] = chr(ord($a[$i]) ^ ord($b[$i]));
  }

  return $a;
}
