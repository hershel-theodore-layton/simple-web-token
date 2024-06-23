/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

use function hash;

function sha256_native(string $data)[defaults]: string {
  return hash('sha256', $data, true);
}
