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
    ): array {
        if ($expectedNonce === null && $validateNonce) {
            throw new InvalidNonceException('No nonce was found in the current session.');
        }

        try {
            // Fast-fail on unknown kid before attempting full decode.
            // If the kid in the JWT header does not exist in the JWKS, the
            // cached key set is stale (key rotation) or the token is forged.
            $kid = $this->extractKidFromHeader($idToken);
            if ($kid !== null) {
                $this->assertKidExists($kid, $jwks);
            }

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
     * Extract the kid (key ID) from the JWT header without full decoding.
     * Returns null if the token is malformed or the header has no kid.
     */
    private function extractKidFromHeader(string $idToken): ?string
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            return null;
        }

        try {
            $header = json_decode(
                base64_decode(strtr($parts[0], '-_', '+/'), true) ?: '',
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (\Throwable) {
            return null;
        }

        return isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;
    }

    /**
     * Assert that the requested kid is present in the JWKS key set.
     *
     * @param  array<string, mixed>  $jwks
     */
    private function assertKidExists(string $kid, array $jwks): void
    {
        $keys = $jwks['keys'] ?? [];

        foreach ($keys as $key) {
            if (isset($key['kid']) && $key['kid'] === $kid) {
                return;
            }
        }

        throw new TokenValidationException(
            "The ID token references key ID '{$kid}' which is not present in the JWKS. "
            .'The signing key may have been rotated.'
        );
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
