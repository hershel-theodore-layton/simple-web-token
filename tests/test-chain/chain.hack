/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\Project_4FotiU1NJwnf\GeneratedTestChain;

use namespace HTL\TestChain;

async function tests_async<T as TestChain\Chain>(
  TestChain\ChainController<T> $controller
)[defaults]: Awaitable<TestChain\ChainController<T>> {
  return $controller
    ->addTestGroup(\HTL\SimpleWebToken\Tests\hash_hmac_test<>)
    ->addTestGroup(\HTL\SimpleWebToken\Tests\simple_web_token_test<>);
}
