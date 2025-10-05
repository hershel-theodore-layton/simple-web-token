/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HTL\{SimpleWebToken, TestChain};
use function HTL\Expect\expect;

<<TestChain\Discover>>
function decoding_test(TestChain\Chain $chain)[]: TestChain\Chain {
  return $chain->group(__FUNCTION__)
    ->testWith2Params(
      'decoding',
      () ==> vec[
        tuple('q', vec[tuple('q', '')]),
        tuple('q=', vec[tuple('q', '')]),
        tuple('q=1', vec[tuple('q', '1')]),
        tuple('q=1&q=2', vec[tuple('q', '1'), tuple('q', '2')]),
        tuple('%41=%42', vec[tuple('A', 'B')]),
      ],
      ($input, $expect) ==> {
        expect(SimpleWebToken\_Private\parse_x_www_form_encoded($input))
          ->toEqual($expect);
      },
    );
}
