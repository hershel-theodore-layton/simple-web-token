/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

enum Validity: int {
  INVALID = 0;
  EXPIRED = 1;
  VALID = 2;
}
