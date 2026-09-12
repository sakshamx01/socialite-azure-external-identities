<?php

namespace SocialiteProviders\AzureExternalIdentities;

use GuzzleHttp\ClientInterface;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use JsonException;
use SocialiteProviders\AzureExternalIdentities\Exceptions\OpenIdConfigurationException;

class OpenIdConfigurationResolver
{
    private const CACHE_TTL_SECONDS = 3600;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly CacheRepository $cache,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function resolve(string $authority): array
    {
        $cacheKey = 'azure_external_id_oidc_'.md5($authority);

        return $this->cache->remember($cacheKey, self::CACHE_TTL_SECONDS, function () use ($authority) {
            $url = rtrim($authority, '/').'/.well-known/openid-configuration';

            try {
                $response = $this->httpClient->request('GET', $url);
                $configuration = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $exception) {
                throw new OpenIdConfigurationException(
                    'OpenID configuration returned invalid JSON from '.$url.': '.$exception->getMessage(),
                    previous: $exception
                );
            } catch (\Throwable $exception) {
                throw new OpenIdConfigurationException(
                    'Unable to fetch OpenID configuration from '.$url.': '.$exception->getMessage(),
                    previous: $exception
                );
            }

            if (! is_array($configuration)) {
                throw new OpenIdConfigurationException('OpenID configuration response was not a JSON object.');
            }

            return $configuration;
        });
    }

    /**
     * @return array<string, mixed>
     */
    public function resolveJwks(string $jwksUri): array
    {
        $cacheKey = 'azure_external_id_jwks_'.md5($jwksUri);

        return $this->cache->remember($cacheKey, self::CACHE_TTL_SECONDS, function () use ($jwksUri) {
            try {
                $response = $this->httpClient->request('GET', $jwksUri);
                $jwks = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $exception) {
                throw new OpenIdConfigurationException(
                    'JWKS endpoint returned invalid JSON: '.$exception->getMessage(),
                    previous: $exception
                );
            } catch (\Throwable $exception) {
                throw new OpenIdConfigurationException(
                    'Unable to fetch JWKS from '.$jwksUri.': '.$exception->getMessage(),
                    previous: $exception
                );
            }

            if (! is_array($jwks)) {
                throw new OpenIdConfigurationException('JWKS response was not a JSON object.');
            }

            return $jwks;
        });
    }

    /**
     * Remove the cached JWKS for the given URI.
     *
     * Called by the provider after a JwksSignatureException to force a fresh
     * key fetch on the next resolveJwks() call, recovering from a key-rotation
     * event without waiting for the TTL to expire naturally.
     */
    public function forgetJwks(string $jwksUri): void
    {
        $this->cache->forget('azure_external_id_jwks_'.md5($jwksUri));
    }

    /**
     * Remove the cached OpenID configuration for the given authority.
     *
     * Provided for symmetry with forgetJwks(); useful when the discovery
     * document itself needs to be refreshed (e.g. endpoint URL changes).
     */
    public function forgetConfiguration(string $authority): void
    {
        $this->cache->forget('azure_external_id_oidc_'.md5($authority));
    }
}
