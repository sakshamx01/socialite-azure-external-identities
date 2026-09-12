<?php

namespace SocialiteProviders\AzureExternalIdentities;

use SocialiteProviders\Manager\OAuth2\User;

/**
 * Entra External ID–specific Socialite user object.
 *
 * Extends the standard User with typed, IDE-autocomplete-friendly accessors
 * for all Entra-specific claims that go beyond the generic Socialite fields.
 *
 * @see https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
 */
class AzureEiUser extends User
{
    /**
     * The Azure AD Object ID of the user (oid claim).
     * Stable across sign-ins; use this as the primary user identifier.
     */
    public function getObjectId(): ?string
    {
        return $this->getRawClaim('oid');
    }

    /**
     * The Entra tenant ID in which the user's account exists (tid claim).
     */
    public function getTenantId(): ?string
    {
        return $this->getRawClaim('tid');
    }

    /**
     * Unix timestamp when the user authenticated (auth_time claim).
     * Present when the auth request included max_age or prompt=login.
     */
    public function getAuthTime(): ?int
    {
        $authTime = $this->getRawClaim('auth_time');

        return is_numeric($authTime) ? (int) $authTime : null;
    }

    /**
     * Unix timestamp when the token was issued (iat claim).
     */
    public function getIssuedAt(): ?int
    {
        $iat = $this->getRawClaim('iat');

        return is_numeric($iat) ? (int) $iat : null;
    }

    /**
     * Authentication methods references (amr claim).
     * Common values: 'pwd' (password), 'mfa' (MFA), 'otp', 'hwk' (hardware key).
     *
     * @return array<int, string>
     */
    public function getAuthenticationMethods(): array
    {
        $amr = $this->getRawClaim('amr');

        return is_array($amr) ? $amr : [];
    }

    /**
     * The policy (user flow) name under which this token was issued (tfp claim).
     */
    public function getPolicy(): ?string
    {
        return $this->getRawClaim('tfp') ?? $this->getRawClaim('acr');
    }

    /**
     * The session ID associated with this sign-in (sid claim).
     * Used for front-channel logout session matching.
     */
    public function getSessionId(): ?string
    {
        return $this->getRawClaim('sid');
    }

    /**
     * The issuer URI of the token (iss claim).
     */
    public function getIssuer(): ?string
    {
        return $this->getRawClaim('iss');
    }

    /**
     * Read a custom Entra External ID extension attribute by its claim name.
     *
     * Custom attributes configured in the Entra admin center appear as claims
     * prefixed with 'extension_', e.g. 'extension_JobTitle'.
     *
     * Example: $user->getCustomAttribute('extension_JobTitle')
     */
    public function getCustomAttribute(string $claimName): mixed
    {
        return $this->getRawClaim($claimName);
    }

    /**
     * Check if the user authenticated using MFA.
     */
    public function authenticatedWithMfa(): bool
    {
        return in_array('mfa', $this->getAuthenticationMethods(), true);
    }

    /**
     * @return mixed
     */
    private function getRawClaim(string $key): mixed
    {
        return $this->user[$key] ?? null;
    }
}
