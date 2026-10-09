/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken\Tests;

use namespace HH\Lib\{Str, Vec};
use namespace HTL\{SimpleWebToken, TestChain};
use function HTL\Expect\expect;
use function base64_encode, rawurlencode;

<<TestChain\Discover>>
function simple_web_token_test(TestChain\Chain $chain)[]: TestChain\Chain {
  $right_now = 1719138710;
  $in_future = 1719138711;
  $secret_key = SimpleWebToken\this_is_the_secret_key('SECRET_KEY');

  // Sign raw bytes so fixtures can exercise alternate encodings of field names.
  $parse_signed = (string $raw, bool $strict) ==> {
    $hmac = SimpleWebToken\hash_hmac(
      SimpleWebToken\sha256_pure<>,
      $raw,
      $secret_key,
    )
      |> base64_encode($$);
    $serialized = $raw.'&HMACSHA256='.($strict ? rawurlencode($hmac) : $hmac);
    return $strict
      ? SimpleWebToken\parse_strict($serialized)
      : SimpleWebToken\parse($serialized);
  };

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
    ->testWith2Params(
      'test_malformed_expiration_is_invalid',
      () ==> Vec\map(
        vec[
          '',
          'yesterday',
          '-1',
          '+1',
          ' 1',
          '1 ',
          "1\n",
          '1.5',
          '1e3',
          '100junk',
          '9223372036854775808',
          '-9223372036854775809',
        ],
        $expires_on ==> vec[tuple($expires_on, false), tuple($expires_on, true)],
      )
        |> Vec\flatten($$),
      ($expires_on, $strict) ==> {
        $fields = vec[tuple(SimpleWebToken\Token::EXPIRES_ON, $expires_on)];
        $token = $strict
          ? SimpleWebToken\parse_strict(
            SimpleWebToken\sign_strict($fields, $secret_key),
          )
          : SimpleWebToken\parse(SimpleWebToken\sign($fields, $secret_key));
        expect($token->validate($secret_key, $right_now))
          ->toEqual(SimpleWebToken\Validity::INVALID);
        expect($token->isOkay($secret_key, $right_now))->toBeFalse();
      },
    )
    ->testWith3Params(
      'test_duplicate_expiration_is_invalid',
      () ==> Vec\map(
        vec[
          tuple('1', '2'),
          tuple((string)$in_future, (string)$in_future),
          tuple('1', (string)$in_future),
          tuple((string)$in_future, '1'),
          tuple((string)$in_future, 'yesterday'),
        ],
        $pair ==> vec[
          tuple($pair[0], $pair[1], false),
          tuple($pair[0], $pair[1], true),
        ],
      )
        |> Vec\flatten($$),
      ($first, $second, $strict) ==> {
        $fields = vec[
          tuple(SimpleWebToken\Token::EXPIRES_ON, $first),
          tuple(SimpleWebToken\Token::EXPIRES_ON, $second),
        ];
        $token = $strict
          ? SimpleWebToken\parse_strict(
            SimpleWebToken\sign_strict($fields, $secret_key),
          )
          : SimpleWebToken\parse(SimpleWebToken\sign($fields, $secret_key));
        expect($token->validate($secret_key, $right_now))
          ->toEqual(SimpleWebToken\Validity::INVALID);
        expect($token->isOkay($secret_key, $right_now))->toBeFalse();
      },
    )
    ->testWith2Params(
      'test_invalid_reserved_fields',
      () ==> Vec\map(
        vec[
          'Issuer=one&Issuer=one',
          'Issuer=one&Issuer=two',
          'Issuer=two&Issuer=one',
          'Issuer=&Issuer=one',
          'Issuer=one&%49ssuer=two',
          '%49ssuer=one&Issuer=two',
          'Audience=one&Audience=one',
          'Audience=one&Audience=two',
          'Audience=two&Audience=one',
          'Audience=&Audience=one',
          'Audience=one&%41udience=two',
          '%41udience=one&Audience=two',
          'ExpiresOn=1&%45xpiresOn=2',
          '%45xpiresOn=1&ExpiresOn=2',
          'HMACSHA256=extra',
          'HMACSHA256',
          '%48MACSHA256=extra',
          'role=reader&HMACSHA256=extra',
          'role=reader&HMACSHA256',
          'role=reader&%48MACSHA256=extra',
          '%48MACSHA256=one&%48MACSHA256=two',
          // Invalid reserved fields take precedence over expiration.
          'ExpiresOn=1&Issuer=one&Issuer=two',
          'ExpiresOn=1&Audience=one&Audience=two',
        ],
        $raw ==> vec[tuple($raw, false), tuple($raw, true)],
      )
        |> Vec\flatten($$),
      ($raw, $strict) ==> {
        $token = $parse_signed($raw, $strict);
        expect($token->validate($secret_key, $right_now))
          ->toEqual(SimpleWebToken\Validity::INVALID);
        expect($token->isOkay($secret_key, $right_now))->toBeFalse();
      },
    )
    ->testWith2Params(
      'test_appending_fields_after_the_signature_is_invalid',
      () ==> Vec\map(
        vec[
          '&HMACSHA256=extra',
          '&%48MACSHA256=extra',
          '&Issuer=two',
          '&Audience=two',
          '&ExpiresOn=0',
          '&role=admin',
        ],
        $suffix ==> vec[tuple($suffix, false), tuple($suffix, true)],
      )
        |> Vec\flatten($$),
      ($suffix, $strict) ==> {
        $fields = vec[tuple('Issuer', 'one'), tuple('Audience', 'one')];
        $token = $strict
          ? SimpleWebToken\parse_strict(
            SimpleWebToken\sign_strict($fields, $secret_key).$suffix,
          )
          : SimpleWebToken\parse(
            SimpleWebToken\sign($fields, $secret_key).$suffix,
          );
        expect($token->validate($secret_key, $right_now))
          ->toEqual(SimpleWebToken\Validity::INVALID);
        expect($token->isOkay($secret_key, $right_now))->toBeFalse();
      },
    )
    ->testWith2Params(
      'test_valid_reserved_fields_and_duplicate_ordinary_claims',
      () ==> Vec\map(
        vec[
          '',
          'Issuer=one',
          'Audience=one',
          'Issuer=&Audience=',
          'Issuer=%FF',
          'Audience=%C0%AF',
          'Issuer=%E2%98%83&Audience=%E2%98%83',
          '%49ssuer=one&%41udience=one&%45xpiresOn='.(string)$in_future,
          'Issuer=one&Audience=one&role=reader&role=writer',
          'issuer=one&issuer=two&audience=one&audience=two',
          'claim=Issuer%3Done%26Issuer%3Dtwo%26HMACSHA256%3Dextra',
        ],
        $raw ==> vec[tuple($raw, false), tuple($raw, true)],
      )
        |> Vec\flatten($$),
      ($raw, $strict) ==> {
        $token = $parse_signed($raw, $strict);
        expect($token->validate($secret_key, $right_now))
          ->toEqual(SimpleWebToken\Validity::VALID);
        expect($token->isOkay($secret_key, $right_now))->toBeTrue();
      },
    )
    ->test('test_strict_expiration_is_optional_and_expires_on_time', () ==> {
      $without_expiration = SimpleWebToken\sign_strict(
        vec[tuple('role', 'reader'), tuple('role', 'writer')],
        $secret_key,
      )
        |> SimpleWebToken\parse_strict($$);
      expect($without_expiration->validate($secret_key, $right_now))
        ->toEqual(SimpleWebToken\Validity::VALID);
      expect($without_expiration->isOkay($secret_key, $right_now))->toBeTrue();

      $with_expiration = SimpleWebToken\sign_strict(
        vec[tuple(SimpleWebToken\Token::EXPIRES_ON, (string)$in_future)],
        $secret_key,
      )
        |> SimpleWebToken\parse_strict($$);
      expect($with_expiration->validate($secret_key, $right_now))
        ->toEqual(SimpleWebToken\Validity::VALID);
      expect($with_expiration->validate($secret_key, $in_future))
        ->toEqual(SimpleWebToken\Validity::EXPIRED);
      expect($with_expiration->isOkay($secret_key, $in_future))->toBeFalse();
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
        expect($token->validate($secret_key, $right_now))
          ->toEqual(SimpleWebToken\Validity::VALID);
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
