/** simple-web-token is MIT licensed, see /LICENSE. */
namespace HTL\Project_4FotiU1NJwnf\GeneratedTestChain;

use namespace HTL\TestChain;
use type HTL\Pragma\Pragmas;

<<file: Pragmas(vec['PhaLinters', 'digest:c3c9084e0a8a6af58462'])>>

async function tests_async(
  TestChain\ChainController<\HTL\TestChain\Chain> $controller,
)[defaults]: Awaitable<TestChain\ChainController<\HTL\TestChain\Chain>> {
  return $controller
    ->addTestGroup(\HTL\SimpleWebToken\Tests\decoding_test<>)
    ->addTestGroup(\HTL\SimpleWebToken\Tests\hash_hmac_test<>)
    ->addTestGroup(\HTL\SimpleWebToken\Tests\simple_web_token_test<>)
    ->addTestGroup(\HTL\SimpleWebToken\Tests\strict_spec_test<>);
}
