<?php

namespace SocialiteProviders\AzureExternalIdentities\Tests;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use SocialiteProviders\AzureExternalIdentities\Exceptions\InvalidNonceException;
use SocialiteProviders\AzureExternalIdentities\Exceptions\TokenValidationException;
use SocialiteProviders\AzureExternalIdentities\IdTokenVerifier;

class IdTokenVerifierTest extends TestCase
{
    private IdTokenVerifier $verifier;

    /** @var array<string, mixed> RSA key pair generated for tests */
    private array $keyPair;

    protected function setUp(): void
    {
        parent::setUp();
        $this->verifier = new IdTokenVerifier();
        $this->keyPair  = $this->generateRsaKeyPair();
    }

    // -----------------------------------------------------------------------
    // Audience (aud) validation
    // -----------------------------------------------------------------------

    public function test_it_accepts_a_token_with_matching_string_audience(): void
    {
        $token  = $this->buildToken(['aud' => 'my-client-id', 'nonce' => 'abc']);
        $claims = $this->verifier->verify($token, 'my-client-id', 'abc', $this->jwks());

        $this->assertSame('my-client-id', $claims['aud']);
    }

    public function test_it_accepts_a_token_with_matching_array_audience(): void
    {
        $token  = $this->buildToken(['aud' => ['my-client-id', 'other'], 'nonce' => 'abc']);
        $claims = $this->verifier->verify($token, 'my-client-id', 'abc', $this->jwks());

        $this->assertContains('my-client-id', $claims['aud']);
    }

    public function test_it_rejects_token_with_wrong_audience(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessageMatches('/audience/i');

        $token = $this->buildToken(['aud' => 'wrong-client', 'nonce' => 'abc']);
        $this->verifier->verify($token, 'my-client-id', 'abc', $this->jwks());
    }

    // -----------------------------------------------------------------------
    // Nonce validation
    // -----------------------------------------------------------------------

    public function test_it_accepts_a_token_with_matching_nonce(): void
    {
        $token  = $this->buildToken(['aud' => 'client', 'nonce' => 'secret-nonce']);
        $claims = $this->verifier->verify($token, 'client', 'secret-nonce', $this->jwks());

        $this->assertSame('secret-nonce', $claims['nonce']);
    }

    public function test_it_rejects_token_with_wrong_nonce(): void
    {
        $this->expectException(InvalidNonceException::class);

        $token = $this->buildToken(['aud' => 'client', 'nonce' => 'bad-nonce']);
        $this->verifier->verify($token, 'client', 'expected-nonce', $this->jwks());
    }

    public function test_it_throws_when_session_nonce_is_missing_and_validation_enabled(): void
    {
        $this->expectException(InvalidNonceException::class);
        $this->expectExceptionMessageMatches('/No nonce/i');

        $token = $this->buildToken(['aud' => 'client', 'nonce' => 'x']);
        $this->verifier->verify($token, 'client', null, $this->jwks(), validateNonce: true);
    }

    public function test_it_skips_nonce_when_validation_disabled(): void
    {
        $token  = $this->buildToken(['aud' => 'client']);
        $claims = $this->verifier->verify($token, 'client', null, $this->jwks(), validateNonce: false);

        $this->assertSame('client', $claims['aud']);
    }

    // -----------------------------------------------------------------------
    // Expiry validation (handled by firebase/php-jwt)
    // -----------------------------------------------------------------------

    public function test_it_rejects_an_expired_token(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessageMatches('/expired/i');

        $token = $this->buildToken(['aud' => 'client', 'nonce' => 'x', 'exp' => time() - 3600]);
        $this->verifier->verify($token, 'client', 'x', $this->jwks());
    }

    // -----------------------------------------------------------------------
    // Signature validation
    // -----------------------------------------------------------------------

    public function test_it_rejects_a_token_signed_with_a_different_key(): void
    {
        $this->expectException(TokenValidationException::class);

        $otherKey = $this->generateRsaKeyPair();
        // Build token with current key pair but verify against other key's JWKS
        $token = $this->buildToken(['aud' => 'client', 'nonce' => 'x']);
        $this->verifier->verify($token, 'client', 'x', $this->jwks($otherKey));
    }

    // -----------------------------------------------------------------------
    // decodeWithoutVerification
    // -----------------------------------------------------------------------

    public function test_decode_without_verification_returns_claims(): void
    {
        $token  = $this->buildToken(['aud' => 'client', 'sub' => 'user-123']);
        $claims = $this->verifier->decodeWithoutVerification($token);

        $this->assertSame('user-123', $claims['sub']);
    }

    public function test_decode_without_verification_rejects_malformed_token(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessageMatches('/malformed/i');

        $this->verifier->decodeWithoutVerification('not.a.jwt.with.five.parts.here');
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * @param  array<string, mixed>  $extraClaims
     */
    private function buildToken(array $extraClaims = []): string
    {
        $payload = array_merge([
            'iss' => 'https://contoso.ciamlogin.com/tenant-id/v2.0',
            'aud' => 'test-client-id',
            'sub' => 'user-object-id',
            'iat' => time(),
            'exp' => time() + 3600,
            'nonce' => 'test-nonce',
        ], $extraClaims);

        return JWT::encode($payload, $this->keyPair['private'], 'RS256', $this->keyPair['kid']);
    }

    /**
     * @param  array<string, mixed>|null  $keyPair
     * @return array<string, mixed>
     */
    private function jwks(?array $keyPair = null): array
    {
        $kp = $keyPair ?? $this->keyPair;

        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'kid' => $kp['kid'],
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'n'   => $kp['n'],
                    'e'   => $kp['e'],
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function generateRsaKeyPair(): array
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);

        return [
            'private' => $privateKey,
            'kid'     => bin2hex(random_bytes(8)),
            'n'       => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e'       => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ];
    }
}
