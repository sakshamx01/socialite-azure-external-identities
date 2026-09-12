<?php

namespace SocialiteProviders\AzureExternalIdentities\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\TestCase;
use SocialiteProviders\AzureExternalIdentities\Exceptions\OpenIdConfigurationException;
use SocialiteProviders\AzureExternalIdentities\OpenIdConfigurationResolver;

class OpenIdConfigurationResolverTest extends TestCase
{
    private function makeResolver(array $responses, int $oidcTtl = 3600, int $jwksTtl = 3600): OpenIdConfigurationResolver
    {
        $mock    = new MockHandler($responses);
        $client  = new Client(['handler' => HandlerStack::create($mock)]);
        $cache   = new Repository(new ArrayStore());

        return new OpenIdConfigurationResolver($client, $cache, $oidcTtl, $jwksTtl);
    }

    // -----------------------------------------------------------------------
    // resolve() — OIDC discovery document
    // -----------------------------------------------------------------------

    public function test_it_fetches_and_returns_oidc_configuration(): void
    {
        $config = ['issuer' => 'https://contoso.ciamlogin.com/tenant/v2.0', 'jwks_uri' => 'https://example.com/keys'];
        $resolver = $this->makeResolver([
            new Response(200, [], json_encode($config)),
        ]);

        $result = $resolver->resolve('https://contoso.ciamlogin.com/tenant/v2.0');

        $this->assertSame($config['issuer'], $result['issuer']);
    }

    public function test_it_caches_the_oidc_configuration(): void
    {
        $config = ['issuer' => 'https://example.com', 'jwks_uri' => 'https://example.com/keys'];
        $resolver = $this->makeResolver([
            new Response(200, [], json_encode($config)),
            // No second response — would throw if cache miss occurred
        ]);

        $resolver->resolve('https://contoso.ciamlogin.com/tenant/v2.0');
        $result = $resolver->resolve('https://contoso.ciamlogin.com/tenant/v2.0'); // should be cached

        $this->assertSame($config['issuer'], $result['issuer']);
    }

    public function test_it_throws_on_invalid_json_from_oidc_endpoint(): void
    {
        $this->expectException(OpenIdConfigurationException::class);
        $this->expectExceptionMessageMatches('/invalid JSON/i');

        $resolver = $this->makeResolver([new Response(200, [], 'not-json')]);
        $resolver->resolve('https://contoso.ciamlogin.com/tenant/v2.0');
    }

    public function test_it_throws_on_non_object_oidc_response(): void
    {
        $this->expectException(OpenIdConfigurationException::class);
        $this->expectExceptionMessageMatches('/JSON object/i');

        $resolver = $this->makeResolver([new Response(200, [], json_encode(['just', 'array']))]);
        $resolver->resolve('https://contoso.ciamlogin.com/tenant/v2.0');
    }

    // -----------------------------------------------------------------------
    // resolveJwks()
    // -----------------------------------------------------------------------

    public function test_it_fetches_and_returns_jwks(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'abc123']]];
        $resolver = $this->makeResolver([new Response(200, [], json_encode($jwks))]);

        $result = $resolver->resolveJwks('https://contoso.ciamlogin.com/keys');

        $this->assertArrayHasKey('keys', $result);
    }

    public function test_it_caches_jwks(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'abc123']]];
        $resolver = $this->makeResolver([
            new Response(200, [], json_encode($jwks)),
            // no second response
        ]);

        $resolver->resolveJwks('https://contoso.ciamlogin.com/keys');
        $result = $resolver->resolveJwks('https://contoso.ciamlogin.com/keys'); // cached

        $this->assertArrayHasKey('keys', $result);
    }

    // -----------------------------------------------------------------------
    // forgetJwks()
    // -----------------------------------------------------------------------

    public function test_forget_jwks_causes_fresh_fetch(): void
    {
        $jwks1 = ['keys' => [['kty' => 'RSA', 'kid' => 'old-key']]];
        $jwks2 = ['keys' => [['kty' => 'RSA', 'kid' => 'new-key']]];

        $resolver = $this->makeResolver([
            new Response(200, [], json_encode($jwks1)),
            new Response(200, [], json_encode($jwks2)),
        ]);

        $uri = 'https://contoso.ciamlogin.com/keys';

        $first = $resolver->resolveJwks($uri);
        $this->assertSame('old-key', $first['keys'][0]['kid']);

        $resolver->forgetJwks($uri);

        $second = $resolver->resolveJwks($uri);
        $this->assertSame('new-key', $second['keys'][0]['kid']);
    }
}
