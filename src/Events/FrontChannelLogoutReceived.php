<?php

namespace SocialiteProviders\AzureExternalIdentities\Events;

/**
 * Fired when Entra External ID sends a front-channel logout notification.
 *
 * Register a listener for this event to invalidate the matching Laravel session.
 *
 * @see https://learn.microsoft.com/en-us/entra/identity-platform/front-channel-logout-uri
 */
class FrontChannelLogoutReceived
{
    /**
     * @param  array<string, mixed>  $claims  Validated logout token claims.
     *                                         Key claims: 'sub', 'sid', 'iss', 'aud', 'iat', 'jti'.
     */
    public function __construct(
        public readonly array $claims,
    ) {
    }

    /**
     * The subject (user object ID) from the logout token.
     */
    public function getSubject(): ?string
    {
        $sub = $this->claims['sub'] ?? null;

        return is_string($sub) ? $sub : null;
    }

    /**
     * The session ID from the logout token (matches 'sid' in the ID token).
     */
    public function getSessionId(): ?string
    {
        $sid = $this->claims['sid'] ?? null;

        return is_string($sid) ? $sid : null;
    }
}
