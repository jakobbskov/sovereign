# Shared auth integration pattern

## Purpose
This document defines the shared authentication integration pattern for Sovereign applications.

The goal is to keep authentication behavior consistent across the Sovereign ecosystem without forcing all applications into the same deployment shape or code structure.

Authentication is treated as shared platform infrastructure, not as app-local invention.

## Scope

This document applies to Sovereign applications that:

use Sovereign Core Auth as the session authority

rely on cookie-based authentication

need a consistent startup and unauthorized handling model

are expected to behave as part of the wider Sovereign portfolio


This document is intended to guide:

* Sovereign Planta

* Sovereign Finance

* Sovereign Strength

future Sovereign applications that join the shared auth model


# Non-goals

This document does not:

* require a shared frontend auth library

* require a single deployment host

* require identical backend implementations across apps

* define user management internals for Sovereign Core Auth

* replace app-specific authorization logic where needed


# Design principles

The shared auth pattern should preserve the broader Sovereign philosophy:

simple and inspectable behavior

operational clarity

minimal hidden state

graceful degradation

self-hosted practicality

low coupling between application logic and auth service internals


Core model

Session ownership

Sovereign Core Auth is the authority for session validity.

Applications do not create their own competing session systems when participating in the shared Sovereign auth model.

Applications may maintain short-lived local auth cache state for performance or user-experience reasons, but this cache must never become the authority.

Trust boundary

The trust boundary is explicit:

the browser presents the shared session cookie

the application backend validates the session via Sovereign Core Auth

the application frontend trusts its own backend response, not direct browser assumptions


Frontends should not assume that the mere presence of a cookie means the user is authenticated.

Shared cookie direction

The ecosystem uses a shared cookie-based model.

At minimum, each participating app should assume:

session continuity depends on the shared Sovereign auth cookie

app backends must forward or validate against the auth authority

frontend auth state must be derived from backend validation results


The exact cookie name may evolve, but all apps must treat the auth cookie as portfolio infrastructure rather than app-local state.

Standard validation flow

Backend validation flow

The expected backend flow is:

1. receive the incoming request from the app frontend


2. extract the shared auth cookie from the request context


3. call the auth validation endpoint


4. interpret the auth response


5. return an app-local normalized auth result to the frontend



Applications should avoid exposing raw auth-service responses directly where a normalized contract improves stability.

Validation responsibilities

Each app backend is responsible for:

validating session state before returning authenticated app data

distinguishing authentication failure from auth service unavailability

logging auth failures in an operationally useful way

avoiding ambiguous fallback states


Standard auth response semantics

At the portfolio level, apps should normalize responses into the following conceptual outcomes.

Authenticated

The user has a valid shared session.

Recommended response shape:

ok: true

authenticated: true

user: basic identity object


The exact user fields may vary, but the contract should clearly indicate that the session is valid and the user identity is known.

Unauthenticated

The request was processed correctly, but the user does not have a valid session.

Recommended behavior:

HTTP 401

authenticated: false

reason: missing_or_invalid_session


Auth service unavailable

The app could not complete validation because the shared auth service was unavailable or unhealthy.

Recommended behavior:

HTTP 503

authenticated: false

reason: auth_unavailable


Forbidden

If an app later needs app-local authorization beyond shared authentication, this should be treated separately from session validity.

Recommended behavior:

HTTP 403

do not overload 401 for permission logic


Frontend boot flow

Each participating app should use a consistent startup model.

Expected startup sequence

1. app shell loads


2. frontend requests app auth status from its own backend


3. backend validates via Sovereign Core Auth


4. frontend renders one of the known auth states



Known frontend auth states

At minimum, apps should support these states:

loading_auth

authenticated

unauthenticated

auth_unavailable


This avoids the common anti-pattern where startup silently fails and the UI just looks broken.

Unauthorized handling

If the user is unauthenticated:

the app should show a clear unauthorized state

the state should not look like a generic crash

the app may provide a link back to the shared login entry point or platform shell


Expired session handling

If a session expires during use:

protected API requests should return normalized unauthenticated results

the frontend should move back into a clear unauthenticated state

the user should not be left in a fake logged-in UI


Error and fallback behavior

Required distinction

All Sovereign apps using shared auth should explicitly distinguish:

invalid or missing session

auth service unavailable

app backend failure unrelated to auth


This distinction matters operationally and avoids misleading debugging.

Logging guidance

Apps should log:

auth validation failures

upstream auth timeouts

malformed auth responses

repeated unauthorized patterns if useful for diagnostics


Apps should avoid:

noisy debug spam in normal operation

leaking secrets or full cookie contents into logs


Timeouts and resilience

Auth validation calls should use bounded timeout behavior.

The app backend should not hang indefinitely while waiting on the auth service.

Where short-lived auth caching is used, it should:

be explicitly time-bounded

reduce unnecessary repeated validation calls

never replace actual validation authority


Backend contract for participating apps

Each Sovereign app backend participating in shared auth should provide a minimal app-local contract, such as:

GET /api/auth/whoami

or an equivalent auth-status endpoint


The endpoint should:

return normalized auth state

be safe for frontend boot checks

avoid requiring the frontend to call Core Auth directly


Minimum backend responsibilities

A participating backend should:

forward or validate the shared session cookie

normalize auth results

protect private app endpoints consistently

distinguish 401 from 503

log failures cleanly


Frontend contract for participating apps

A participating frontend should:

perform an auth check during boot

keep auth state explicit in UI logic

handle expired sessions without ambiguity

avoid assuming the user is logged in based on local state alone

link the user toward the shared login path when unauthenticated


Cross-app navigation and session continuity

The shared auth model exists partly to support a coherent portfolio experience.

When moving between Sovereign apps:

session continuity should come from the shared auth cookie model

apps should not require separate login logic if they participate in shared auth

apps should avoid inventing app-specific pseudo-sessions on top of shared auth


This supports a future platform shell or launcher without requiring immediate monolithic coupling.

Compliance checklist

A Sovereign application can be treated as shared-auth compatible when it satisfies all of the following:

it relies on Sovereign Core Auth as session authority

it validates auth through its backend

it provides a normalized auth status endpoint

it distinguishes 401 from 503

it exposes clear unauthenticated and auth-unavailable frontend states

it avoids treating local cache as auth truth

it supports portfolio-consistent session continuity across apps


Application notes

Sovereign Strength

Sovereign Strength can serve as the early reference implementation for this pattern because it already demonstrates several relevant behaviors:

cookie-based validation

distinction between unauthorized and unavailable auth service

app-local auth status handling

structured auth failure logging


Sovereign Planta

Sovereign Planta should adopt this contract rather than invent its own auth flow.

Sovereign Finance

Sovereign Finance should adopt this contract as part of broader cleanup and launcher compatibility work.

Open questions

The following questions may require later documentation or follow-up issues:

exact normalized JSON schema for auth endpoints

exact shared login entry URL or launcher flow

whether a common frontend helper should later be extracted

whether role or permission semantics should be standardized across apps

whether auth observability should later be documented as its own portfolio contract


Summary

Shared authentication in Sovereign should remain:

centralized in authority

decentralized in implementation

explicit in behavior

distinguishable in failure modes

simple enough that each app can integrate it without local improvisation


That is the point of the pattern: consistency without unnecessary framework theater.