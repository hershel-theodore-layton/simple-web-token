/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use namespace HH\Lib\{C, Dict, Str, Vec};
use function base64_encode;

final class Token {
  const string EXPIRES_ON = 'ExpiresOn';
  const string HMACSHA256 = 'HMACSHA256';

  private dict<string, string> $unique;
  private dict<string, vec<string>> $nonUnique;

  public function __construct(
    private string $raw,
    private ?string $hmac,
    vec<(string, string)> $pairs,
  )[] {
    list($unique, $non_unique) = Dict\group_by($pairs, $p ==> $p[0])
      |> Dict\partition($$, $group ==> C\count($group) === 1);

    $this->unique = Dict\map($unique, $group ==> C\onlyx($group)[1]);
    $this->nonUnique =
      Dict\map($non_unique, $group ==> Vec\map($group, $pair ==> $pair[1]));
  }

  public function getNonUniqueKeys()[]: dict<string, vec<string>> {
    return $this->nonUnique;
  }

  public function getUniqueKeys()[]: dict<string, string> {
    return $this->unique;
  }

  public function isOkay(
    TSecretKey $secret_key,
    int $unix_timestamp,
    (function(string)[_]: string) $hash_func = sha256_pure<>,
  )[ctx $hash_func]: bool {
    return $this->validate($secret_key, $unix_timestamp, $hash_func) ===
      Validity::VALID;
  }

  public function validate(
    TSecretKey $secret_key,
    int $unix_timestamp,
    (function(string)[_]: string) $hash_func = sha256_pure<>,
  )[ctx $hash_func]: Validity {
    $hmac = hash_hmac($hash_func, $this->raw, $secret_key) |> base64_encode($$);
    if ($this->hmac !== $hmac) {
      return Validity::INVALID;
    }

    $expires_on = idx($this->unique, static::EXPIRES_ON)
      |> $$ is null ? null : Str\to_int($$);

    if ($expires_on is nonnull && $expires_on <= $unix_timestamp) {
      return Validity::EXPIRED;
    }

    return Validity::VALID;
  }
}
