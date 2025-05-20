/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HH\Lib\Str;
use namespace HTL\{SimpleWebToken, TestChain};
use function HTL\Expect\expect;

<<TestChain\Discover>>
function simple_web_token_test(TestChain\Chain $chain)[]: TestChain\Chain {
  $right_now = 1719138710;
  $in_future = 1719138711;
  $secret_key = SimpleWebToken\this_is_the_secret_key('SECRET_KEY');

  return $chain->group(__FUNCTION__)
    ->test('test_empty_token', () ==> {
      $serialized = SimpleWebToken\sign(vec[], $secret_key);
      $token = SimpleWebToken\parse($serialized);

      expect($token->isOkay($secret_key, $right_now))
        ->toBeTrue();
      expect($token->validate($secret_key, $right_now))
        ->toEqual(SimpleWebToken\Validity::VALID);

      expect($token->getUniqueKeys())->toBeEmpty();
      expect($token->getNonUniqueKeys())->toBeEmpty();
    })
    ->test('test_token_expires_on_the_exact_second', () ==> {
      $serialized = SimpleWebToken\sign(
        vec[
          tuple('?', '!'),
          tuple(SimpleWebToken\Token::EXPIRES_ON, $in_future.''),
        ],
        $secret_key,
      );
      $token = SimpleWebToken\parse($serialized);

      expect($token->isOkay($secret_key, $right_now))
        ->toBeTrue();
      expect($token->validate($secret_key, $right_now))
        ->toEqual(SimpleWebToken\Validity::VALID);
      expect($token->isOkay($secret_key, $in_future))
        ->toBeFalse();
      expect($token->validate($secret_key, $in_future))
        ->toEqual(SimpleWebToken\Validity::EXPIRED);

      expect($token->getUniqueKeys()['?'])->toEqual('!');
      expect($token->getNonUniqueKeys())->toBeEmpty();
    })
    ->test(
      'test_token_can_contain_duplicate_keys_and_order_is_retained',
      () ==> {
        $serialized = SimpleWebToken\sign(
          vec[
            tuple('?', '!'),
            tuple('a', 'b'),
            tuple('?', '!!'),
            tuple('later', '4'),
            tuple('?', '!!!'),
            tuple('later', '44'),
          ],
          $secret_key,
        );
        $token = SimpleWebToken\parse($serialized);

        expect($token->getUniqueKeys())->toEqual(dict['a' => 'b']);
        expect($token->getNonUniqueKeys())->toEqual(
          dict['?' => vec['!', '!!', '!!!'], 'later' => vec['4', '44']],
        );
      },
    )
    ->test('test_if_you_change_the_token_it_becomes_invalid', () ==> {
      $serialized = SimpleWebToken\sign(vec[tuple('a', 'b')], $secret_key);
      $serialized[0] = 'z';
      $token = SimpleWebToken\parse($serialized);

      expect($token->isOkay($secret_key, $right_now))
        ->toBeFalse();
      expect($token->validate($secret_key, $right_now))
        ->toEqual(SimpleWebToken\Validity::INVALID);
    })
    ->test('test_if_you_dont_provide_a_hmac_your_token_is_invalid', () ==> {
      $serialized = SimpleWebToken\sign(vec[tuple('a', 'b')], $secret_key)
        |> Str\slice($$, 0, Str\search($$, SimpleWebToken\Token::HMACSHA256));
      $token = SimpleWebToken\parse($serialized);

      expect($token->isOkay($secret_key, $right_now))
        ->toBeFalse();
      expect($token->validate($secret_key, $right_now))
        ->toEqual(SimpleWebToken\Validity::INVALID);
    });
}
