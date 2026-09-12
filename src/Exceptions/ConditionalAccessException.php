<?php

namespace SocialiteProviders\AzureExternalIdentities\Exceptions;

/**
 * Thrown when Entra External ID rejects the token request because a
 * Conditional Access policy requires additional action (e.g. MFA, compliant device).
 *
 * The $claimsChallenge string contains the base64url-encoded claims value
 * that must be passed back to the authorization endpoint to satisfy the policy.
 *
 * Usage in your callback route:
 *
 *   try {
 *       $user = Socialite::driver('azure-ei')->user();
 *   } catch (ConditionalAccessException $e) {
 *       return Socialite::driver('azure-ei')
 *           ->with(['claims' => $e->getClaimsChallenge()])
 *           ->redirect();
 *   }
 *
 * @see https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge
 */
class ConditionalAccessException extends AzureExternalIdentitiesException
{
    public function __construct(
        string $message,
        private readonly string $claimsChallenge,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * The raw claims challenge string to pass as the 'claims' parameter
     * on the next authorization request to satisfy the Conditional Access policy.
     */
    public function getClaimsChallenge(): string
    {
        return $this->claimsChallenge;
    }
}
