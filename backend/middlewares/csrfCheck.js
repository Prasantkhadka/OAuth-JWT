/**
 * csrfCheck middleware - double-submit CSRF protection
 *
 * - The server sets a readable `csrfToken` cookie at sign-in/sign-up.
 * - The frontend must send that value in the `X-CSRF-Token` header for state
 *   changing requests. This middleware compares header vs cookie and rejects
 *   the request when they differ or are missing.
 * - This is a simple and stateless double-submit pattern; combine with SameSite
 *   cookie settings and CORS to strengthen protection for production.
 */
export default function csrfCheck(req, res, next) {
  try {
    const cookieToken = req.cookies && req.cookies.csrfToken;
    const headerToken = req.get("x-csrf-token") || req.headers["x-csrf-token"];

    if (!cookieToken || !headerToken) {
      return res.status(403).json({ message: "Missing CSRF token" });
    }

    if (cookieToken !== headerToken) {
      return res.status(403).json({ message: "Invalid CSRF token" });
    }

    return next();
  } catch (err) {
    return res.status(500).json({ message: "CSRF validation error" });
  }
}
