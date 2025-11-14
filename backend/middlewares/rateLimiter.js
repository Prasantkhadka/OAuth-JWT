import rateLimit from "express-rate-limit";

/*
  Rate limiting middleware

  - authLimiter: protects high-volume authentication endpoints (signup/login)
    from brute-force attempts. Configured conservatively (10 req / minute).
  - otpLimiter: stricter limits for OTP-related endpoints to prevent abuse
    (e.g., sending many OTP emails to a target address).

  Adjust windowMs/max values as needed for your deployment traffic patterns.
*/
// General auth rate limiter: protects signup/login endpoints
export const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per windowMs
  message: { message: "Too many auth attempts, please try again later." },
});

// Sensitive actions limiter (OTP endpoints): fewer attempts per window
export const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // limit each IP to 5 OTP requests per window
  message: { message: "Too many OTP requests, please try later." },
});

export default { authLimiter, otpLimiter };
