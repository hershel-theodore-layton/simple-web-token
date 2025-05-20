/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HH\Lib\{PseudoRandom, Vec};
use namespace HTL\{SimpleWebToken, TestChain};
use function HTL\Expect\expect;
use function chr;

<<TestChain\Discover>>
function hash_hmac_test(TestChain\Chain $chain)[]: TestChain\Chain {
  return $chain->group(__FUNCTION__)
    ->testWith2Params(
      'test_sha256_pure',
      ()[leak_safe] ==> Vec\concat(
        // The empty sequence
        vec[''],
        // every single byte
        Vec\range(0, 1 << 7) |> Vec\map($$, chr<>),
        // every single two byte sequence
        Vec\range(0, 1 << 15)
          |> Vec\map($$, $v ==> chr($v >> 8).chr($v & 0xff)),
        // many sequences of random length and random contents
        Vec\range(0, 10000)
          |> Vec\map(
            $$,
            $_ ==> PseudoRandom\string(PseudoRandom\int(3, 10000)),
          ),
      )
        |> Vec\map($$, $str ==> tuple($str, null)),
      ($data, $_)[defaults] ==> {
        expect(SimpleWebToken\sha256_pure($data))->toEqual(
          SimpleWebToken\sha256_native($data),
        );
      },
    )
    ->testWith2Params(
      'test_hash_hmac',
      ()[leak_safe] ==> Vec\concat(
        // The empty cases
        vec[tuple('', ''), tuple('a', ''), tuple('', 'a')],
        // Every single byte key and single byte secret
        Vec\range(0, 1 << 15)
          |> Vec\map($$, $v ==> tuple(chr($v >> 8), chr($v & 0xff))),
        // many keys and data sequences of random length and random contents
        Vec\range(0, 100000)
          |> Vec\map(
            $$,
            $_ ==> tuple(
              PseudoRandom\string(PseudoRandom\int(3, 10000)),
              PseudoRandom\string(PseudoRandom\int(3, 10000)),
            ),
          ),
      )
        |> Vec\map(
          $$,
          $t ==> tuple($t[0], SimpleWebToken\this_is_the_secret_key($t[1])),
        ),
      ($data, $secret_key)[defaults] ==> {
        // Using sha256_native for non-repo auth cold jit performance.
        // The test above `test_sha256_pure` expresses that they are interchangeable
        // with likeliness bordering on absolute certainty.
        expect(SimpleWebToken\hash_hmac(
          SimpleWebToken\sha256_native<>,
          $data,
          $secret_key,
        ))->toEqual(\hash_hmac('sha256', $data, $secret_key, true));
      },
    );
}
