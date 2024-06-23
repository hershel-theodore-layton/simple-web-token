/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\SimpleWebToken;

/**
 * The native `hash(...)` function in hhvm required `[defaults]` before October 2023.
 * By writing it in Hack, we can call it from a pure (`[]`) context.
 * @see `sha256_native` for a non-pure faster implementation.
 */
function sha256_pure(string $data)[]: string {
  return _Private\sha256_pure($data);
}
