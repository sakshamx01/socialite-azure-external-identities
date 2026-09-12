<?php

namespace SocialiteProviders\AzureExternalIdentities;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use SocialiteProviders\AzureExternalIdentities\Exceptions\InvalidNonceException;
use SocialiteProviders\AzureExternalIdentities\Exceptions\TokenValidationException;

class IdTokenVerifier
{
    /**
     * @param  array<string, mixed>  $jwks
     * @return array<string, mixed>
     */
    public function verify(
        string $idToken,
        string $clientId,
        ?string $expectedNonce,
        array $jwks,
        bool $validateNonce = true,
        ?string $expectedPolicy = null,
    ): array {
        if ($expectedNonce === null && $validateNonce) {
            throw new InvalidNonceException('No nonce was found in the current session.');
        }

        try {
            $payload = JWT::decode($idToken, JWK::parseKeySet($jwks, 'RS256'));
        } catch (ExpiredException $exception) {
            throw new TokenValidationException('The ID token has expired.', previous: $exception);
        } catch (SignatureInvalidException $exception) {
            throw new TokenValidationException('The ID token signature is invalid.', previous: $exception);
        } catch (\Throwable $exception) {
            throw new TokenValidationException(
                'Unable to validate the ID token: '.$exception->getMessage(),
                previous: $exception
            );
        }

        $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        $this->assertAudience($claims, $clientId);

        if ($expectedPolicy !== null) {
            $this->assertPolicy($claims, $expectedPolicy);
        }

        if ($validateNonce) {
            $this->assertNonce($claims, $expectedNonce);
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    public function decodeWithoutVerification(string $idToken): array
    {
        $segments = explode('.', $idToken);

        if (count($segments) !== 3) {
            throw new TokenValidationException('The ID token is malformed.');
        }

        $payload = $this->base64UrlDecode($segments[1]);

        try {
            $claims = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new TokenValidationException('The ID token payload is not valid JSON.', previous: $exception);
        }

        if (! is_array($claims)) {
            throw new TokenValidationException('The ID token payload must be a JSON object.');
        }

        return $claims;
    }

    /**
     * Validate the tfp (trust framework policy) or acr claim matches the
     * expected policy. Entra External ID includes tfp in tokens issued via
     * named user flows; acr is the fallback for older tenants.
     *
     * @param  array<string, mixed>  $claims
     */
    private function assertPolicy(array $claims, string $expectedPolicy): void
    {
        // tfp is the primary claim; fall back to acr for older B2C-style tenants.
        $actualPolicy = $claims['tfp'] ?? $claims['acr'] ?? null;

        if (! is_string($actualPolicy)) {
            throw new TokenValidationException(
                "The ID token is missing a policy claim (tfp/acr). Expected: '{$expectedPolicy}'."
            );
        }

        if (strcasecmp($actualPolicy, $expectedPolicy) !== 0) {
            throw new TokenValidationException(
                "The ID token policy does not match. Got: '{$actualPolicy}', expected: '{$expectedPolicy}'."
            );
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertAudience(array $claims, string $clientId): void
    {
        $audience = $claims['aud'] ?? null;

        if (is_array($audience)) {
            if (! in_array($clientId, $audience, true)) {
                throw new TokenValidationException('The ID token audience does not match the configured client ID.');
            }

            return;
        }

        if ($audience !== $clientId) {
            throw new TokenValidationException('The ID token audience does not match the configured client ID.');
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertNonce(array $claims, ?string $expectedNonce): void
    {
        $tokenNonce = $claims['nonce'] ?? null;

        if (! is_string($tokenNonce) || $tokenNonce === '' || $tokenNonce !== $expectedNonce) {
            throw new InvalidNonceException('The ID token contains an invalid nonce.');
        }
    }

    private function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;

        if ($remainder > 0) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        if ($decoded === false) {
            throw new TokenValidationException('Unable to decode the ID token payload.');
        }

        return $decoded;
    }
}
