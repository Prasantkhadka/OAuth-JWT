# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) (or [oxc](https://oxc.rs) when used in [rolldown-vite](https://vite.dev/guide/rolldown)) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.

---

## Auth integration (summary)

- Cookies and tokens exchanged with backend:

  - `token` (HttpOnly): short-lived access token set by the backend after sign-in/sign-up.
  - `refreshToken` (HttpOnly): longer-lived token used to obtain new access tokens.
  - `csrfToken` (readable): a token the frontend must read from cookies and include in the
    `X-CSRF-Token` header for protected state-changing requests (double-submit pattern).

- Frontend behavior:
  - Use the `api` axios instance which is configured with `withCredentials: true` so
    cookies are sent automatically.
  - The axios interceptor reads the `csrfToken` cookie and sets the `X-CSRF-Token` header.
  - Login/Signup flow: POST `/api/auth/login` or `/api/auth/signup` -> server sets cookies,
    then frontend calls `/api/user/profile` to obtain the logged-in user.
  - Password reset flow: `ForgotPassword` -> calls `/api/auth/send-reset-otp` -> `VerifyOtp` ->
    calls `/api/auth/verify-reset-otp` (receives verificationToken) -> `ResetPassword` -> calls
    `/api/auth/forgot-password` with verificationToken or OTP + new password.

## Frontend environment variables

- `VITE_API_URL` (optional) - your backend base URL (defaults to http://localhost:4000).

# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) (or [oxc](https://oxc.rs) when used in [rolldown-vite](https://vite.dev/guide/rolldown)) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
