/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\Project_4FotiU1NJwnf\GeneratedTestChain;

use namespace HTL\TestChain;

async function tests_async(
  TestChain\ChainController<\HTL\TestChain\Chain> $controller
)[defaults]: Awaitable<TestChain\ChainController<\HTL\TestChain\Chain>> {
  return $controller
    ->addTestGroup(\HTL\SimpleWebToken\Tests\decoding_test<>)
    ->addTestGroup(\HTL\SimpleWebToken\Tests\hash_hmac_test<>)
    ->addTestGroup(\HTL\SimpleWebToken\Tests\simple_web_token_test<>);
}
