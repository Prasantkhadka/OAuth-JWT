# Backend - OAuth-JWT

This backend serves the authentication API used by the frontend. Below is a short summary of the auth flow and required environment variables.

## Auth flow (high level)

- Sign up / Sign in

  - POST /api/auth/signup and POST /api/auth/login accept credentials and, on success,
    set three cookies:
    - `token` (HttpOnly) — short-lived access JWT used by `userAuth` to protect routes.
    - `refreshToken` (HttpOnly) — longer-lived JWT used to rotate / refresh access tokens.
    - `csrfToken` (readable) — used by the frontend to send in `X-CSRF-Token` header (double-submit CSRF).
  - The server stores only a SHA-256 hash of the refresh token in the user's `refreshTokens` array.

- Token rotation

  - POST /api/auth/refresh validates the refresh token, ensures the hashed value exists in DB,
    then rotates to a new access + refresh pair and replaces the stored hash.

- Revoke / Logout

  - POST /api/auth/revoke or POST /api/auth/logout removes the hashed refresh token from the DB
    and clears cookies on the client.

- OTP flows

  - POST /api/auth/send-reset-otp sends a one-time code to an email (rate-limited).
  - POST /api/auth/verify-reset-otp validates the OTP and returns a short-lived verification token.
  - POST /api/auth/forgot-password accepts either `{email, otp, newPassword}` or
    `{email, newPassword, verificationToken}` to reset the password.

- Google OAuth
  - GET /api/auth/google -> redirects to Google consent screen.
  - GET /api/auth/google/callback -> exchanges code, verifies id_token, issues cookies, and
    redirects to the frontend callback route.

## Security notes

- Refresh tokens in the DB are hashed (SHA-256). The raw refresh token is only sent to the client
  in an HttpOnly cookie.
- A readable `csrfToken` cookie is issued at authentication time; the frontend must include it in
  `X-CSRF-Token` for protected state-changing endpoints (`csrfCheck` middleware verifies it).
- Rate limiting is applied to auth and OTP endpoints.

## Required environment variables

- `JWT_SECRET` (required) - secret to sign access tokens.
- `REFRESH_TOKEN_SECRET` (optional) - secret to sign refresh tokens. If not set, `JWT_SECRET` is used.
- `RESET_TOKEN_SECRET` (optional) - secret for short-lived verification tokens used in reset flows.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` - for Google OAuth.
- `FRONTEND_URL` - frontend origin used to redirect after OAuth.
- `MONGODB_URI` - connection string to MongoDB.
- `SENDER_EMAIL`, `SMTP_USER`, `SMTP_PASS`, `SMTP_HOST`, `SMTP_PORT` - for nodemailer SMTP transport.
- `NODE_ENV` - to toggle production cookie settings.

## Quick dev notes

- Use HTTPS (or set NODE_ENV=development and accept insecure cookies) when testing secure cookie behavior.
- Ensure the server runs with cookie-parser and CORS configured to allow credentials from the frontend origin.
