<?php

namespace SocialiteProviders\AzureExternalIdentities\Exceptions;

/**
 * Thrown when an ID token's signature cannot be verified against the cached
 * JWKS. This distinct exception type is used by the provider to detect a
 * potential key-rotation event and trigger a single cache-busting retry
 * before surfacing the error to the caller.
 */
class JwksSignatureException extends TokenValidationException
{
}
