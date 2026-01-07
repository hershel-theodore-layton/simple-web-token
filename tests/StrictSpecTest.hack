/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HTL\{SimpleWebToken, TestChain};
use function HTL\Expect\expect;
use function rawurlencode;

<<TestChain\Discover>>
function strict_spec_test(TestChain\Chain $chain)[]: TestChain\Chain {
  $fields = vec[tuple('Data', 'Datum')];
  $secret_key = SimpleWebToken\this_is_the_secret_key('SECRET_KEY');

  return $chain->group(__FUNCTION__)
    ->test(
      'tokens_signed_according_to_the_spec_must_double_encode_their_hmacs',
      () ==> {
        $strict = SimpleWebToken\sign_strict($fields, $secret_key);
        $weak = SimpleWebToken\sign($fields, $secret_key);

        // Note, this token ends with %3D, which is a url encoded `=`.
        // The `=` is the padding of the base64 operation.
        expect($strict)->toEqual(
          'Data=Datum&HMACSHA256=Dpis2gbXgK%2BihpApcvoSBzCc1yqNrYqmoUElx6uc%2BGI%3D',
        );
        // Note, this token encodes the name data, but the hmac ends with a `=`.
        expect($weak)->toEqual(
          'Data=Datum&HMACSHA256=Dpis2gbXgK+ihpApcvoSBzCc1yqNrYqmoUElx6uc+GI=',
        );

        // Strict tokens can be parsed by strict, but not by weak.
        expect(SimpleWebToken\parse_strict($strict)->isOkay($secret_key, 0))
          ->toBeTrue();
        expect(SimpleWebToken\parse($strict)->isOkay($secret_key, 0))
          ->toBeFalse();

        // Weak tokens can be parsed by weak and by strict.
        expect(SimpleWebToken\parse($weak)->isOkay($secret_key, 0))->toBeTrue();
        expect(SimpleWebToken\parse_strict($weak)->isOkay($secret_key, 0))
          ->toBeTrue();
      },
    )
    ->test('change_space_encoding_for_non_conforming_implementations', () ==> {
      expect(SimpleWebToken\sign_strict(vec[tuple(' ', ' ')], $secret_key))
        ->toEqual(
          '+=+&HMACSHA256=5Ph2KMiUjIPcX8Ne99eVvFVGu1KWE%2BicT%2F4mdxyro60%3D',
        );

      // This weakening of the spec is required to interoperate with modules
      // that use percent encoding for spaces, instead of +. The spec says it
      // should be plus, so that is the default behavior.
      expect(SimpleWebToken\sign_strict(
        vec[tuple(' ', ' ')],
        $secret_key,
        shape('url_encoder_for_data' => rawurlencode<>),
      ))
        ->toEqual(
          '%20=%20&HMACSHA256=Zjm9LwqiWtycHc7Z4NDxhppTP%2Bv0cRp8IC8knV25Q1I%3D',
        );
    });
}
