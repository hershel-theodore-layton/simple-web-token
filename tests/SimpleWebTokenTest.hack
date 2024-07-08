/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HH\Lib\Str;
use namespace HTL\SimpleWebToken;
use type Facebook\HackTest\HackTest;
use function Facebook\FBExpect\expect;

final class SimpleWebTokenTest extends HackTest {
  const int RIGHT_NOW = 1719138710;
  const int IN_FUTURE = 1719138711;
  const string SECRET_KEY = 'SECRET_KEY';

  public function test_empty_token(): void {
    $serialized = SimpleWebToken\sign(vec[], static::secretKey());
    $token = SimpleWebToken\parse($serialized);

    expect($token->isOkay(static::secretKey(), static::RIGHT_NOW))->toBeTrue();
    expect($token->validate(static::secretKey(), static::RIGHT_NOW))
      ->toEqual(SimpleWebToken\Validity::VALID);

    expect($token->getUniqueKeys())->toBeEmpty();
    expect($token->getNonUniqueKeys())->toBeEmpty();
  }

  public function test_token_expires_on_the_exact_second(): void {
    $serialized = SimpleWebToken\sign(
      vec[
        tuple('?', '!'),
        tuple(SimpleWebToken\Token::EXPIRES_ON, static::IN_FUTURE.''),
      ],
      static::secretKey(),
    );
    $token = SimpleWebToken\parse($serialized);

    expect($token->isOkay(static::secretKey(), static::RIGHT_NOW))
      ->toBeTrue();
    expect($token->validate(static::secretKey(), static::RIGHT_NOW))
      ->toEqual(SimpleWebToken\Validity::VALID);
    expect($token->isOkay(static::secretKey(), static::IN_FUTURE))
      ->toBeFalse();
    expect($token->validate(static::secretKey(), static::IN_FUTURE))
      ->toEqual(SimpleWebToken\Validity::EXPIRED);

    expect($token->getUniqueKeys()['?'])->toEqual('!');
    expect($token->getNonUniqueKeys())->toBeEmpty();
  }

  public function test_token_can_contain_duplicate_keys_and_order_is_retained(
  ): void {
    $serialized = SimpleWebToken\sign(
      vec[
        tuple('?', '!'),
        tuple('a', 'b'),
        tuple('?', '!!'),
        tuple('later', '4'),
        tuple('?', '!!!'),
        tuple('later', '44'),
      ],
      static::secretKey(),
    );
    $token = SimpleWebToken\parse($serialized);

    expect($token->getUniqueKeys())->toEqual(dict['a' => 'b']);
    expect($token->getNonUniqueKeys())->toEqual(
      dict['?' => vec['!', '!!', '!!!'], 'later' => vec['4', '44']],
    );
  }

  public function test_if_you_change_the_token_it_becomes_invalid(): void {
    $serialized =
      SimpleWebToken\sign(vec[tuple('a', 'b')], static::secretKey());
    $serialized[0] = 'z';
    $token = SimpleWebToken\parse($serialized);

    expect($token->isOkay(static::secretKey(), static::RIGHT_NOW))
      ->toBeFalse();
    expect($token->validate(static::secretKey(), static::RIGHT_NOW))
      ->toEqual(SimpleWebToken\Validity::INVALID);
  }

  public function test_if_you_dont_provide_a_hmac_your_token_is_invalid(
  ): void {
    $serialized = SimpleWebToken\sign(vec[tuple('a', 'b')], static::secretKey())
      |> Str\slice($$, 0, Str\search($$, SimpleWebToken\Token::HMACSHA256));
    $token = SimpleWebToken\parse($serialized);

    expect($token->isOkay(static::secretKey(), static::RIGHT_NOW))
      ->toBeFalse();
    expect($token->validate(static::secretKey(), static::RIGHT_NOW))
      ->toEqual(SimpleWebToken\Validity::INVALID);
  }

  private static function secretKey()[]: SimpleWebToken\TSecretKey {
    return SimpleWebToken\this_is_the_secret_key(static::SECRET_KEY);
  }
}
