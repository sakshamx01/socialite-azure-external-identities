# Entra External ID — Development Branch Reference

> All 20 branches are checked out from `main`. Each branch contains a single focused change.
> This file documents what changed, why it matters, and the Microsoft reference behind each decision.

---

## Quick Index

| # | Branch | Type | Priority |
|---|--------|------|----------|
| 1 | `security/iss-issuer-validation` | 🔴 Security | Critical |
| 2 | `security/iat-token-freshness` | 🔴 Security | High |
| 3 | `security/tfp-acr-policy-validation` | 🔴 Security | Critical |
| 4 | `security/auth-time-max-age` | 🔴 Security | High |
| 5 | `security/jwks-kid-fast-fail` | 🔴 Security | High |
| 6 | `feat/logout-id-token-hint` | 🟢 Feature | Medium |
| 7 | `feat/refresh-token-grant` | 🟢 Feature | Medium |
| 8 | `feat/prompt-parameter` | 🟢 Feature | Low |
| 9 | `feat/login-hint` | 🟢 Feature | Low |
| 10 | `feat/domain-hint` | 🟢 Feature | Low |
| 11 | `feat/ui-locales` | 🟢 Feature | Low |
| 12 | `feat/front-channel-logout` | 🟢 Feature | Medium |
| 13 | `feat/acr-values-step-up` | 🟢 Feature | Medium |
| 14 | `feat/claims-parameter` | 🟢 Feature | Low |
| 15 | `feat/claims-challenge-ca` | 🟢 Feature | High |
| 16 | `feat/jwks-key-rotation-retry` | 🔴 Security | Critical |
| 17 | `feat/configurable-cache-ttl` | 🟢 Feature | Medium |
| 18 | `feat/configurable-cache-store` | 🟢 Feature | Low |
| 19 | `feat/typed-user-accessors` | 🟢 Feature | Low |
| 20 | `test/full-test-suite` | 🧪 Testing | Critical |

---

---

## 1. `security/iss-issuer-validation`

### What Is the Change?
Added **issuer (`iss`) claim validation** to the ID token verification flow.

**Files changed:**
- `src/IdTokenVerifier.php` — New `assertIssuer()` private method. New `?string $expectedIssuer` parameter added to `verify()`.
- `src/Provider.php` — `resolveIdTokenClaims()` reads `$configuration['issuer']` from the OIDC discovery document and passes it into `verify()`.

### Why Is This Important?
The `iss` (issuer) claim identifies which authority issued the JWT token. **The package was not validating this claim at all.**

This means: if an attacker created their own Entra External ID tenant, issued a token with a valid signature from *their* tenant but with your app's `client_id` as the audience — the token would pass verification and the attacker would be logged in as a user on your application.

The fix reads the trusted issuer directly from the OIDC discovery document (the authority-canonical value), so it never needs to be hardcoded.

### What Changes at Runtime?
- Every ID token now has its `iss` claim compared against the issuer from the OIDC discovery document.
- A mismatch throws `TokenValidationException` with both the actual and expected values in the message.
- No config changes needed — the expected issuer is derived automatically.

### Microsoft Reference
> *"Your application must validate the issuer (iss) claim."*
- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-tokens
- OIDC Core spec §3.1.3.7 rule #2 — https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation


### Commit 
    '''security: validate iss (issuer) claim on ID token
    
    Adds assertIssuer() to IdTokenVerifier and wires the issuer from the
    OIDC discovery document into verify(). Without this, a token from any
    other Entra tenant with a valid signature would be accepted as login.
    
    Ref: https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-tokens'''

---

## 2. `security/iat-token-freshness`

### What Is the Change?
Added optional **token freshness validation** based on the `iat` (issued-at) claim.

**Files changed:**
- `src/IdTokenVerifier.php` — New `assertTokenFreshness()` private method. New `?int $freshnessWindowSeconds` parameter added to `verify()`.
- `src/Provider.php` — New `getTokenFreshnessWindow()` method reads `token_freshness_ttl` from config. Passes it to `verify()`.

### Why Is This Important?
A token has an `exp` (expiration) claim, but that window is often 1 hour. An authorization code stolen during the OAuth2 redirect could be replayed up to 1 hour later and still produce a valid token.

The `iat` (issued-at) claim records the exact moment the token was created. By enforcing a **freshness window** (e.g., 600 seconds), you ensure the callback must happen within 10 minutes of token issuance — which is far more than enough for any real user while closing the replay window significantly.

The OIDC spec (rule #9) says the `iat` claim *should* be checked for sanity.

### What Changes at Runtime?
- **Off by default** — only activates when `token_freshness_ttl` is set in `config/services.php`.
- Tokens older than the configured seconds throw `TokenValidationException` with the actual age and limit in the message.

```php
// config/services.php
'azure-ei' => [
    'token_freshness_ttl' => 600, // reject tokens older than 10 minutes
]
```

### Microsoft Reference
- OIDC Core §3.1.3.7 rule #9 — https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-tokens

---

## 3. `security/tfp-acr-policy-validation`

### What Is the Change?
Added **user flow / policy claim validation** (`tfp` / `acr`) to the ID token verification flow.

**Files changed:**
- `src/IdTokenVerifier.php` — New `assertPolicy()` private method. New `?string $expectedPolicy` parameter added to `verify()`.
- `src/Provider.php` — `resolveIdTokenClaims()` passes `$this->getPolicy()` as `$expectedPolicy`. When no policy is configured the check is skipped.

### Why Is This Important?
When you use named user flows or policies (e.g. a sign-in flow `B2X_1_SignIn` and a password-reset flow `B2X_1_PasswordReset`), Entra External ID stamps the `tfp` claim in the token to record which policy produced it.

**Without this check**, a user who completes the password-reset flow gets a valid, signed token — but with `tfp=B2X_1_PasswordReset`. If that token is submitted to your sign-in callback, the package will accept it as a sign-in. This is a documented cross-policy substitution attack.

The check falls back from `tfp` to `acr` for compatibility with older B2C-style tenants.

### What Changes at Runtime?
- **No effect** when `policy` is not set in config (check is skipped).
- When `policy` is set, every token's `tfp` or `acr` claim must match exactly (case-insensitive).
- A mismatch throws `TokenValidationException` with both actual and expected policy names.

### Microsoft Reference
> *"Applications that use policies must verify the tfp or acr claim."*
- https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#claims

---

## 4. `security/auth-time-max-age`

### What Is the Change?
Added **`auth_time` claim enforcement** when the `max_age` OIDC parameter is used.

**Files changed:**
- `src/IdTokenVerifier.php` — New `assertAuthTime()` private method. New `?int $maxAge` parameter added to `verify()`.
- `src/Provider.php` — `redirect()` persists `max_age` to the Laravel session. New `getSessionMaxAge()` reads and clears it on callback. Value passed to `verify()`.

### Why Is This Important?
`max_age` is an OIDC parameter that tells Entra: *"Only accept this authentication if the user authenticated within the last N seconds."* When `max_age` is sent, Entra includes an `auth_time` claim in the returned token.

**The package was forwarding `max_age` to Entra but never checking `auth_time` in the returned token.** This made `max_age` purely cosmetic — the UI restriction existed but the app never verified the claim.

OIDC spec rule #11 explicitly requires the app to verify: `now() <= auth_time + max_age`.

### What Changes at Runtime?
- **No effect** if `max_age` is not passed via `->with(['max_age' => N])`.
- When used, `max_age` is saved to the session during `redirect()`.
- On callback, if `now() > auth_time + max_age`, throws `TokenValidationException`.
- The session key is automatically cleared after a single use (no replay risk).

### Microsoft Reference
- OIDC Core §3.1.3.7 rule #11 — https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
- `max_age` definition — https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

---

## 5. `security/jwks-kid-fast-fail`

### What Is the Change?
Added **fast-fail on unknown `kid`** before attempting JWT decode.

**Files changed:**
- `src/IdTokenVerifier.php` — New `extractKidFromHeader()` method (decodes only the JWT header). New `assertKidExists()` method scans the JWKS keys array. Both called inside `verify()` before `JWT::decode()`.

### Why Is This Important?
Every Entra signing key has a `kid` (Key ID). Every JWT header references the `kid` of the key that signed it. The JWKS returned by Entra contains a list of current valid keys, each with their `kid`.

`firebase/php-jwt` (the underlying library) tries every key in the JWKS when decoding if no `kid` match is found. This produces a generic `SignatureInvalidException` — which looks identical to a forged token error.

Two problems with that:
1. **Ambiguous failure** — you can't tell if the key was rotated or if someone sent a forged token.
2. **Masks rotation events** — the rotation retry logic (branch #16) depends on knowing *specifically* that the `kid` was not found.

By checking `kid` presence upfront, the failure is explicit: *"key ID 'abc123' not found in JWKS — key may have been rotated."*

### What Changes at Runtime?
- Adds a lightweight pre-check on every verified token (just a JWT header decode + array scan).
- Unknown `kid` → throws `TokenValidationException` with the specific key ID and rotation hint.
- No `kid` in token header → the check is skipped, behaviour unchanged.

### Microsoft Reference
> *"Each key in the JWKS has a kid property that matches the kid in the JWT header."*
- https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover
- RFC 7517 §4.5 (JWK `kid` parameter) — https://www.rfc-editor.org/rfc/rfc7517#section-4.5

---

## 6. `feat/logout-id-token-hint`

### What Is the Change?
Added optional **`id_token_hint` parameter** to `getLogoutUrl()`.

**Files changed:**
- `src/Provider.php` — `getLogoutUrl()` now accepts `?string $idTokenHint = null` as a second parameter. When provided, it's appended to the logout URL query string.

### Why Is This Important?
When a user is sent to Entra's logout endpoint without an `id_token_hint`, Entra shows an **intermediate "Are you sure you want to sign out?" page** before redirecting back to your app.

Passing the raw ID token string that was issued to the user at login tells Entra exactly which session to terminate — enabling **immediate, silent, single sign-out** with no confirmation page.

### What Changes at Runtime?
- Fully backward compatible — `$idTokenHint` defaults to `null`, existing calls unchanged.
- When provided, `id_token_hint=<token>` is appended to the logout URL.

```php
// Store id_token on login:
session(['id_token' => $user->accessTokenResponseBody['id_token']]);

// Use on logout:
$url = Socialite::driver('azure-ei')
    ->getLogoutUrl(route('home'), session('id_token'));
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/external-id/customers/sample-web-app-dotnet-sign-in#sign-out
- OIDC RP-Initiated Logout §2 — https://openid.net/specs/openid-connect-rpinitiated-1_0.html

---

## 7. `feat/refresh-token-grant`

### What Is the Change?
Added a `refreshToken()` method to exchange a refresh token for new tokens.

**Files changed:**
- `src/Provider.php` — New public `refreshToken(string $refreshToken): array` method. POSTs to the token endpoint with `grant_type=refresh_token`.

### Why Is This Important?
The package collects the `refresh_token` from the token response and stores it on `$user->refreshToken`. But it provides **no way to actually use it**. Developers who need to refresh an expired access token must implement the raw Guzzle HTTP call themselves.

This adds the missing half of the token lifecycle. Common use cases:
- Access tokens expire (usually 1 hour). Instead of forcing the user to re-login, silently refresh.
- Long-running background jobs that need a valid access token.

### What Changes at Runtime?
- Returns the full token response array: `access_token`, `refresh_token`, `id_token`, `expires_in`, `token_type`.
- Respects the `proxy` config setting.
- Throws `TokenValidationException` on JSON decode failures.

```php
$tokens = Socialite::driver('azure-ei')->refreshToken($user->refreshToken);
// Store $tokens['access_token'] and $tokens['refresh_token']
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token

---

## 8. `feat/prompt-parameter`

### What Is the Change?
Added `withPrompt()` fluent helper method with validation.

**Files changed:**
- `src/Provider.php` — New `withPrompt(string $prompt): static` method. Validates against the four OIDC-allowed values before passing via `with()`.

### Why Is This Important?
The OIDC `prompt` parameter controls the sign-in page behaviour. It was already passable via `->with(['prompt' => '...'])` but with no validation and no discoverability. A typed method makes this a first-class API.

| Value | What it does |
|-------|-------------|
| `login` | Force re-authentication even if SSO session exists |
| `none` | Silent — return error if interaction needed |
| `consent` | Always show the consent screen |
| `select_account` | Show the account picker |

```php
Socialite::driver('azure-ei')->withPrompt('login')->redirect();
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-authorization-code

---

## 9. `feat/login-hint`

### What Is the Change?
Added `withLoginHint()` fluent helper method.

**Files changed:**
- `src/Provider.php` — New `withLoginHint(string $loginHint): static` method. Passes `login_hint` to the authorization URL.

### Why Is This Important?
In many flows the app already knows the user's email — for example, after the user types it into a local form. Passing `login_hint` pre-fills the email on Entra's sign-in page, skipping one step and reducing friction.

```php
Socialite::driver('azure-ei')
    ->withLoginHint($request->input('email'))
    ->redirect();
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-authorization-code

---

## 10. `feat/domain-hint`

### What Is the Change?
Added `withDomainHint()` fluent helper method.

**Files changed:**
- `src/Provider.php` — New `withDomainHint(string $domainHint): static` method. Passes `domain_hint` to the authorization URL.

### Why Is This Important?
When an Entra External ID tenant has multiple federated identity providers (Google, Facebook, Apple), users land on a home-realm-discovery page to choose one. `domain_hint` bypasses this page entirely and redirects the user **directly** to the specified provider's login.

Essential for apps that already know which social provider the user uses, or apps with a "Continue with Google" button.

```php
Socialite::driver('azure-ei')->withDomainHint('google.com')->redirect();
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-authorization-code

---

## 11. `feat/ui-locales`

### What Is the Change?
Added `withUiLocales()` fluent helper method.

**Files changed:**
- `src/Provider.php` — New `withUiLocales(string $locales): static` method. Passes `ui_locales` (space-separated BCP47 language tags) to the authorization URL.

### Why Is This Important?
Without `ui_locales`, Entra's sign-in page language defaults to the browser's `Accept-Language` header — which may not match the language of your Laravel app.

For multi-locale applications (e.g. a French user using your French-language app), explicitly passing `ui_locales` ensures the Entra sign-in page is also rendered in French.

```php
Socialite::driver('azure-ei')->withUiLocales(app()->getLocale())->redirect();
// or with multiple preferences:
Socialite::driver('azure-ei')->withUiLocales('fr-FR de en')->redirect();
```

### Microsoft Reference
- OIDC Core §3.1.2.1 (`ui_locales`) — https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
- https://learn.microsoft.com/en-us/entra/external-id/customers/concept-branding-customers

---

## 12. `feat/front-channel-logout`

### What Is the Change?
Added a `FrontChannelLogout` handler class and `FrontChannelLogoutReceived` event.

**Files changed:**
- `src/FrontChannelLogout.php` — New class. `handle(Request $request)` validates the `logout_token` JWT and fires the event.
- `src/Events/FrontChannelLogoutReceived.php` — New event class with `getSubject()` and `getSessionId()` helpers.

### Why Is This Important?
**Front-channel logout** is how Entra External ID notifies your application that a user has signed out of *another* app sharing the same SSO session.

Without handling this, if a user signs out from App A, their session in App B (your app) remains active. This breaks the SSO contract and is a security concern — the user believes they signed out everywhere but they haven't.

Entra sends a GET/POST to a registered `frontchannel_logout_uri` with a signed `logout_token`. This token must be:
1. Signature-verified against the JWKS
2. Checked for audience (your `client_id`)
3. Checked for the required `events` claim (backchannel-logout marker)
4. Confirmed to have NO `nonce` claim (a security requirement in the spec)

When valid, the `FrontChannelLogoutReceived` event is fired and your app invalidates the matching session.

```php
// Route registration:
Route::get('/auth/frontchannel-logout', function (Request $request) {
    app(FrontChannelLogout::class)->handle($request);
    return response()->noContent();
});

// Event listener:
Event::listen(FrontChannelLogoutReceived::class, function ($event) {
    // $event->getSessionId() — match against stored sid
    // $event->getSubject()   — user's object ID
});
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/front-channel-logout-uri
- OIDC Front-Channel Logout spec — https://openid.net/specs/openid-connect-frontchannel-1_0.html

---

## 13. `feat/acr-values-step-up`

### What Is the Change?
Added `withAcrValues()` fluent helper method for step-up authentication.

**Files changed:**
- `src/Provider.php` — New `withAcrValues(string $acrValues): static` method. Passes `acr_values` to the authorization URL.

### Why Is This Important?
**Step-up authentication** allows requiring a higher assurance level for specific high-risk actions — even when the user is already logged in.

Example: a user is logged in normally. They try to transfer money. Your app triggers a new authentication request with `acr_values` requiring MFA. Entra re-authenticates the user with MFA and returns a new token. The app validates the `acr` claim in the returned token confirms MFA was performed.

Without this, the only way to require MFA mid-session is to force a full re-login.

```php
// Require MFA before sensitive action
Socialite::driver('azure-ei')
    ->withAcrValues('urn:microsoft:policies:mfa')
    ->redirect();

// On callback, validate the acr claim
$user = Socialite::driver('azure-ei')->user();
abort_unless($user->user['acr'] === 'urn:microsoft:policies:mfa', 403);
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/developer-glossary#authentication-context-class-reference

---

## 14. `feat/claims-parameter`

### What Is the Change?
Added `withClaims()` fluent helper method for the OIDC `claims` request parameter.

**Files changed:**
- `src/Provider.php` — New `withClaims(array $claims): static` method. JSON-encodes the array and passes it as the `claims` parameter.

### Why Is This Important?
The OIDC `claims` parameter lets you request **specific claims** by name, including marking them as `essential` (required). This is especially useful for:

- **Custom Entra External ID extension attributes** (like `extension_JobTitle`, `extension_Department`) — these are custom attributes configured in the Entra admin portal that won't appear in the token unless explicitly requested.
- Requesting only what you need rather than adding broad scopes.

```php
Socialite::driver('azure-ei')
    ->withClaims([
        'id_token' => [
            'email'              => ['essential' => true],
            'extension_JobTitle' => null,  // custom CIAM attribute
        ],
    ])
    ->redirect();
```

### Microsoft Reference
- OIDC Core §5.5 — https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
- https://learn.microsoft.com/en-us/entra/external-id/customers/concept-custom-extensions

---

## 15. `feat/claims-challenge-ca`

### What Is the Change?
Added `ConditionalAccessException` and automatic detection of Conditional Access (CA) policy errors from the token endpoint.

**Files changed:**
- `src/Exceptions/ConditionalAccessException.php` — New exception class. Carries the `$claimsChallenge` string and exposes it via `getClaimsChallenge()`.
- `src/Provider.php` — `getAccessTokenResponse()` now inspects the error response. When `error=interaction_required` or `error=insufficient_claims` is detected, throws `ConditionalAccessException` instead of `TokenValidationException`.

### Why Is This Important?
**Conditional Access policies** are enforced by Entra for things like: require MFA, require a compliant device, restrict by network location. When a CA policy triggers during token exchange, Entra returns an error:

```json
{
  "error": "interaction_required",
  "claims": "<base64-encoded-claims-challenge>",
  "error_description": "AADSTS50076: MFA required..."
}
```

Without this change, the app throws a generic `TokenValidationException` and the user is stuck — there is no indication of what went wrong or how to fix it.

With `ConditionalAccessException`, the app can **catch and re-drive the user** through the CA policy by passing the claims challenge back to Entra:

```php
try {
    $user = Socialite::driver('azure-ei')->user();
} catch (ConditionalAccessException $e) {
    // Redirect user to satisfy the Conditional Access policy (e.g. MFA)
    return Socialite::driver('azure-ei')
        ->with(['claims' => $e->getClaimsChallenge()])
        ->redirect();
}
```

Apps not using CA policies are completely unaffected — the detection only triggers on `interaction_required` / `insufficient_claims` errors that contain AADSTS codes.

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview

---

## 16. `feat/jwks-key-rotation-retry`

### What Is the Change?
Added **automatic JWKS cache-bust and retry** when token verification fails due to a stale key.

**Files changed:**
- `src/Exceptions/JwksSignatureException.php` — New exception extending `TokenValidationException`. Used only for key-mismatch failures so retry logic is surgical.
- `src/IdTokenVerifier.php` — Throws `JwksSignatureException` on `SignatureInvalidException` and unknown `kid`.
- `src/OpenIdConfigurationResolver.php` — New `forgetJwks(string $uri)` method clears the JWKS cache key. New `forgetConfiguration(string $authority)` clears the OIDC config cache.
- `src/Provider.php` — New `verifyIdTokenWithRotationRetry()` method. On `JwksSignatureException`: busts JWKS cache → fetches fresh keys → retries `verify()` once.

### Why Is This Important?
Microsoft rotates Entra External ID signing keys **every ~6 weeks** and can perform **emergency rotations without notice** during security incidents.

**What happens when a rotation occurs WITHOUT this fix:**
1. Your app has the old JWKS cached with key `kid=abc123`.
2. Microsoft starts signing tokens with new key `kid=xyz789`.
3. Every single login attempt fails: `TokenValidationException: signature invalid`.
4. This continues for up to **1 hour** (the JWKS cache TTL).
5. Result: **Every user locked out for up to an hour.** No clear error, looks like a bug.

**What happens WITH this fix:**
1. Same rotation occurs.
2. First verify attempt fails → `JwksSignatureException` is caught.
3. JWKS cache is busted immediately → fresh keys fetched from Microsoft.
4. Verify retried with fresh keys → succeeds in milliseconds.
5. Result: **User logs in normally. Zero downtime. Self-healing.**

The retry is strictly **one attempt only** — so forged tokens still fail after the retry.

### Microsoft Reference
> *"We recommend that your application caches OIDC metadata for no more than 24 hours and refreshes it if a token fails to validate."*
- https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover
- https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover#how-to-assess-if-your-application-will-be-affected-and-what-to-do-about-it

---

## 17. `feat/configurable-cache-ttl`

### What Is the Change?
Made OIDC discovery document and JWKS cache TTLs **configurable** instead of hardcoded.

**Files changed:**
- `src/OpenIdConfigurationResolver.php` — Replaced hardcoded `CACHE_TTL_SECONDS = 3600` constant with `$oidcCacheTtl` and `$jwksCacheTtl` constructor parameters (both default to `3600`).
- `src/Provider.php` — Added `oidc_cache_ttl` and `jwks_cache_ttl` to `additionalConfigKeys()`. `configurationResolver()` reads and passes them to the constructor.

### Why Is This Important?
The 1-hour TTL is a one-size-fits-all value. Different production environments have different needs:

| Scenario | Ideal TTL |
|----------|-----------|
| High-security app | 5–15 minutes |
| Standard production | 1 hour (current default) |
| Low-traffic app | 6–24 hours |
| Staging/dev | 0–60 seconds |

Microsoft recommends no more than **24 hours** — but says apps should refresh on failure, not by relying on the TTL. The rotation retry (branch #16) handles the failure case; this change handles the schedule.

```php
'azure-ei' => [
    'oidc_cache_ttl' => 3600,   // OIDC discovery document cache: 1 hour
    'jwks_cache_ttl' => 3600,   // JWKS key set cache: 1 hour
]
```

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover#how-to-assess-if-your-application-will-be-affected-and-what-to-do-about-it

---

## 18. `feat/configurable-cache-store`

### What Is the Change?
Added a `cache_store` config key to allow **isolating OIDC/JWKS data to a dedicated cache store**.

**Files changed:**
- `src/Provider.php` — Added `cache_store` to `additionalConfigKeys()`. `configurationResolver()` now calls `Cache::store($this->getConfig('cache_store') ?: null)`.

### Why Is This Important?
By default, the package uses Laravel's default cache store — which is often `file` or a shared `redis` instance used by the entire application.

Sharing the cache store means OIDC/JWKS data competes for eviction with sessions, queues, rate limiters, and other app data. In a high-traffic app, a cache eviction event could clear the JWKS cache and cause unnecessary JWKS re-fetches for every login.

Pointing to a dedicated `redis` store keeps this data isolated, persistent, and fast.

```php
'azure-ei' => [
    'cache_store' => 'redis', // isolate to a dedicated store
]
```

---

## 19. `feat/typed-user-accessors`

### What Is the Change?
Added `AzureEiUser` — a new typed user class with dedicated accessor methods for all Entra External ID-specific claims.

**Files changed:**
- `src/AzureEiUser.php` — New class extending `SocialiteProviders\Manager\OAuth2\User`. Adds 10 typed, documented methods.
- `src/Provider.php` — `mapUserToObject()` now returns `AzureEiUser` instead of `User`. Import added.

### Why Is This Important?
Entra External ID tokens carry many rich, app-relevant claims beyond what the standard Socialite `User` maps: `oid`, `tid`, `auth_time`, `amr`, `sid`, `tfp`, custom `extension_*` attributes, etc.

Currently, accessing these requires `$user->user['oid']` — not IDE-discoverable, not documented in code, requires knowing exact claim name strings.

`AzureEiUser` provides a clean, typed, IDE-autocomplete-friendly API while remaining fully backward compatible (it extends `User`, so all existing code still works).

| Method | Claim | Purpose |
|--------|-------|---------|
| `getObjectId()` | `oid` | Stable user identifier — use as DB primary key |
| `getTenantId()` | `tid` | Entra tenant the user belongs to |
| `getAuthTime()` | `auth_time` | When the user last authenticated |
| `getIssuedAt()` | `iat` | When this token was issued |
| `getAuthenticationMethods()` | `amr` | `['pwd']`, `['pwd', 'mfa']`, etc. |
| `getPolicy()` | `tfp`/`acr` | Which user flow/policy issued the token |
| `getSessionId()` | `sid` | For front-channel logout session matching |
| `getIssuer()` | `iss` | The authority that issued the token |
| `getCustomAttribute($name)` | any | Custom CIAM extension attributes |
| `authenticatedWithMfa()` | `amr` | Returns `true` if MFA was used |

### Microsoft Reference
- https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference

---

## 20. `test/full-test-suite`

### What Is the Change?
Added a complete PHPUnit test suite covering `IdTokenVerifier` and `OpenIdConfigurationResolver`.

**Files changed:**
- `composer.json` — Added `phpunit/phpunit ^11.0` and `mockery/mockery ^1.6` to `require-dev`. Added `autoload-dev` PSR-4 entry for `tests/`.
- `phpunit.xml` — PHPUnit configuration file.
- `tests/IdTokenVerifierTest.php` — 9 test cases for the token verifier.
- `tests/OpenIdConfigurationResolverTest.php` — 7 test cases for the OIDC resolver.

### Why Is This Important?
**The package had zero automated tests.** Every one of the 19 security fixes and features in this branch list is only reliable if backed by tests. A Composer package that handles authentication tokens for production Laravel applications must have the same rigour as the auth libraries it depends on.

**What the tests cover:**

`IdTokenVerifierTest`:
- ✅ Accepts token with matching string audience
- ✅ Accepts token with matching array audience
- ✅ Rejects token with wrong audience
- ✅ Accepts token with matching nonce
- ✅ Rejects token with wrong nonce
- ✅ Throws when session nonce missing but validation enabled
- ✅ Skips nonce check when validation disabled
- ✅ Rejects expired token
- ✅ Rejects token signed with a different key
- ✅ `decodeWithoutVerification()` returns claims
- ✅ `decodeWithoutVerification()` rejects malformed token

`OpenIdConfigurationResolverTest`:
- ✅ Fetches and returns OIDC config
- ✅ Caches OIDC config (no second HTTP call)
- ✅ Throws on invalid JSON response
- ✅ Throws on non-object JSON response
- ✅ Fetches and returns JWKS
- ✅ Caches JWKS (no second HTTP call)
- ✅ `forgetJwks()` causes a fresh fetch

Tests use **real RSA key pairs** (via `openssl_pkey_new`) — no mocked JWT libraries, so signature verification is tested for real. Guzzle `MockHandler` and in-memory `ArrayStore` mean no live HTTP or Redis calls.

```bash
composer install
./vendor/bin/phpunit
```

### Microsoft Reference
- MSAL test patterns — https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/tree/dev/tests

---

*Document maintained on `main` branch. Updated: 2026-09-12*
