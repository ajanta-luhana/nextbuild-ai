# ADR-0005: Password authentication and network hardening
Supersedes the passwordless local mode. `AUTH_MODE=password` (default): users have scrypt-hashed passwords (N=2^15, parameters stored per hash),
a password policy (10+ chars, common-password and user-name checks), generic login errors, equal-time verification for unknown users,
account lockout (`MAX_FAILED_LOGINS`/`LOCKOUT_MINUTES`) and a per-IP login throttle. The first account is created through a one-time setup screen and
becomes admin; further registration needs `ALLOW_REGISTRATION=1`.
Sessions: HttpOnly, SameSite=Strict cookie (Secure over HTTPS), HMAC-hashed at rest, 12 h absolute and 30 min idle expiry, max 10 per user,
all other sessions revoked on password change. Mutations need the CSRF header, a same-host Origin and `application/json`.
Network: Host-header allowlist (DNS-rebinding defence), COOP/CORP/HSTS headers, and the server refuses a non-loopback bind unless `ALLOW_REMOTE_BIND=1`.
`AUTH_MODE=proxy` trusts `X-Forwarded-User` from an authenticated reverse proxy that must strip that header from client requests.
Forgot password: a one-time recovery code (160 bits, stored only as a hash, rotated on every use) is shown once at sign-up and can be regenerated in Account security; using it resets the password and signs out all sessions, and failed attempts count toward the same lockout. Optional TOTP two-step verification (RFC 6238, no replay of a used code, drift window of one step) is enabled per user in Account security. Roles: `admin` (first account) and `builder`; every project and run is owner-scoped.
Still out of scope: SSO, e-mail based reset (the app has no mail server), TLS termination (use a reverse proxy), multi-node storage.
