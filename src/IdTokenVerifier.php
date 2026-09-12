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
        ?int $maxAge = null,
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

        if ($maxAge !== null) {
            $this->assertAuthTime($claims, $maxAge);
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
     * Enforce the max_age parameter by validating the auth_time claim.
     *
     * When max_age is included in the authorization request, Entra adds an
     * auth_time claim to the token. The OIDC spec (§3.1.3.7, rule 11)
     * requires the RP to verify: now() <= auth_time + max_age.
     *
     * @param  array<string, mixed>  $claims
     */
    private function assertAuthTime(array $claims, int $maxAge): void
    {
        $authTime = $claims['auth_time'] ?? null;

        if (! is_int($authTime)) {
            throw new TokenValidationException(
                'The ID token is missing the auth_time claim required by max_age validation.'
            );
        }

        if (time() > $authTime + $maxAge) {
            throw new TokenValidationException(
                'The user authentication is too old to satisfy the max_age constraint. '
                ."auth_time={$authTime}, max_age={$maxAge}s, now=".time().'.'
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
