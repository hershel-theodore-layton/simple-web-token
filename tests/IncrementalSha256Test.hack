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
    ->testWith2Params(
      'test_incremental_sha256_splits',
      () ==> {
        $cases = dict[];
        foreach (vec[0, 55, 56, 63, 64, 65, 127, 128, 129, 257] as $length) {
          // Exercise every split, including empty writes and long continuations.
          for ($split = 0; $split <= $length; ++$split) {
            $cases[(string)$length.' bytes split at '.(string)$split] =
              tuple($length, $split);
          }
        }
        return $cases;
      },
      (int $length, int $split)[defaults] ==> {
        $data = incremental_sha256_test_data($length);
        $expected = SimpleWebToken\sha256_native($data);
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
      },
    )
    ->testWith2Params(
      'test_incremental_sha256_byte_writes',
      ()[defaults] ==> {
        $cases = dict[];
        foreach (vec[0, 55, 56, 63, 64, 65, 127, 128, 129, 257] as $length) {
          $data = incremental_sha256_test_data($length);
          $cases[(string)$length.' bytes'] =
            tuple($data, SimpleWebToken\sha256_native($data));
        }
        return $cases;
      },
      (string $data, string $expected) ==> {
        // These writes are sequential operations on one hash state.
        $state = _Private\sha_256_init();
        for ($i = 0; $i < Str\length($data); ++$i) {
          _Private\sha_256_write(inout $state, vec[ord($data[$i])]);
        }
        expect(_Private\sha_256_close(inout $state))->toEqual($expected);
      },
    );
}

function incremental_sha256_test_data(int $length)[]: string {
  $data = '';
  for ($i = 0; $i < $length; ++$i) {
    $data .= chr($i & 0xff);
  }
  return $data;
}
