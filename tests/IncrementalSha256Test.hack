/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HH\Lib\Str;
use namespace HTL\{SimpleWebToken, TestChain};
use namespace HTL\SimpleWebToken\_Private;
use function HTL\Expect\expect;
use function chr, ord;

<<TestChain\Discover>>
function incremental_sha256_test(TestChain\Chain $chain)[]: TestChain\Chain {
  return $chain->group(__FUNCTION__)
    ->test('test_incremental_sha256', ()[defaults] ==> {
      foreach (vec[0, 55, 56, 63, 64, 65, 127, 128, 129, 257] as $length) {
        $data = '';
        for ($i = 0; $i < $length; ++$i) {
          $data .= chr($i & 0xff);
        }
        $expected = SimpleWebToken\sha256_native($data);
        // Exercise every split, including empty writes and long continuations.
        for ($split = 0; $split <= $length; ++$split) {
          $state = _Private\sha_256_init();
          foreach (
            vec[Str\slice($data, 0, $split), '', Str\slice($data, $split)] as
              $part
          ) {
            _Private\sha_256_write(
              inout $state,
              _Private\cast_string_to_memory_t($part),
            );
          }
          expect(_Private\sha_256_close(inout $state))->toEqual($expected);
        }
        // Repeated short writes fill the buffer across multiple blocks.
        $state = _Private\sha_256_init();
        for ($i = 0; $i < $length; ++$i) {
          _Private\sha_256_write(inout $state, vec[ord($data[$i])]);
        }
        expect(_Private\sha_256_close(inout $state))->toEqual($expected);
      }
    });
}
