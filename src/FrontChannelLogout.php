<?php

namespace SocialiteProviders\AzureExternalIdentities;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use SocialiteProviders\AzureExternalIdentities\Events\FrontChannelLogoutReceived;
use SocialiteProviders\AzureExternalIdentities\Exceptions\TokenValidationException;

/**
 * Handles Entra External ID front-channel logout notifications.
 *
 * When a user signs out of another app sharing the same Entra SSO session,
 * Entra sends a GET or POST request to a registered frontchannel_logout_uri.
 * This class validates the logout_token JWT and fires FrontChannelLogoutReceived.
 *
 * ## Setup
 *
 * 1. Register the route (ideally a GET route):
 *
 *    Route::get('/auth/azure-ei/frontchannel-logout', function (Request $request) {
 *        app(FrontChannelLogout::class)->handle($request);
 *        return response()->noContent();
 *    });
 *
 * 2. Register the URI in your Entra app registration:
 *    Authentication → Front-channel logout URL → https://yourapp.com/auth/azure-ei/frontchannel-logout
 *
 * 3. Listen for the event to invalidate the user's session:
 *
 *    Event::listen(FrontChannelLogoutReceived::class, function ($event) {
 *        // Find and invalidate the session matching $event->getSessionId()
 *        // or $event->getSubject() (user's object ID)
 *    });
 *
 * @see https://learn.microsoft.com/en-us/entra/identity-platform/front-channel-logout-uri
 * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html
 */
class FrontChannelLogout
{
    public function __construct(
        private readonly OpenIdConfigurationResolver $resolver,
        private readonly string $clientId,
        private readonly string $authority,
    ) {
    }

    /**
     * Validate the logout_token in the request and fire FrontChannelLogoutReceived.
     *
     * @throws TokenValidationException if the logout token is missing or invalid.
     */
    public function handle(Request $request): void
    {
        $logoutToken = $request->input('logout_token');

        if (! is_string($logoutToken) || $logoutToken === '') {
            throw new TokenValidationException('The front-channel logout request is missing a logout_token.');
        }

        $claims = $this->validateLogoutToken($logoutToken);

        Event::dispatch(new FrontChannelLogoutReceived($claims));
    }

    /**
     * @return array<string, mixed>
     */
    private function validateLogoutToken(string $logoutToken): array
    {
        $configuration = $this->resolver->resolve($this->authority);

        if (! isset($configuration['jwks_uri']) || ! is_string($configuration['jwks_uri'])) {
            throw new TokenValidationException('OpenID configuration is missing a JWKS URI.');
        }

        $jwks = $this->resolver->resolveJwks($configuration['jwks_uri']);

        try {
            $payload = JWT::decode($logoutToken, JWK::parseKeySet($jwks, 'RS256'));
        } catch (\Throwable $exception) {
            throw new TokenValidationException(
                'The logout_token could not be validated: '.$exception->getMessage(),
                previous: $exception
            );
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        $this->assertLogoutTokenClaims($claims);

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertLogoutTokenClaims(array $claims): void
    {
        // Logout tokens MUST NOT contain a nonce claim.
        if (isset($claims['nonce'])) {
            throw new TokenValidationException('The logout_token must not contain a nonce claim.');
        }

        // Must contain either sid or sub (or both).
        if (! isset($claims['sid']) && ! isset($claims['sub'])) {
            throw new TokenValidationException('The logout_token must contain a sid or sub claim.');
        }

        // Must contain the events claim with the backchannel logout event key.
        $events = $claims['events'] ?? null;
        $logoutEventKey = 'http://schemas.openid.net/event/backchannel-logout';

        if (! is_array($events) || ! isset($events[$logoutEventKey])) {
            throw new TokenValidationException(
                'The logout_token is missing the required backchannel-logout events claim.'
            );
        }

        // Audience must include this application's client_id.
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];

        if (! in_array($this->clientId, $audiences, true)) {
            throw new TokenValidationException(
                'The logout_token audience does not include this application.'
            );
        }
    }
}
