import express from "express";
import {
  logout,
  sendVerificationOtp,
  signIn,
  signUp,
  verifyEmail,
  isEmailVerified,
  sendResetOtp,
  resetPassword,
  googleAuthRedirect,
  googleAuthCallback,
  refreshTokens,
  revokeRefreshToken,
  verifyResetOtp,
} from "../controllers/authController.js";
import userAuth from "../middlewares/userAuth.js";
import { authLimiter, otpLimiter } from "../middlewares/rateLimiter.js";
import csrfCheck from "../middlewares/csrfCheck.js";

const authRouter = express.Router();

authRouter.post("/signup", authLimiter, signUp);
authRouter.post("/login", authLimiter, signIn);
authRouter.post("/logout", csrfCheck, logout);

authRouter.post(
  "/send-verification-otp",
  userAuth,
  csrfCheck,
  otpLimiter,
  sendVerificationOtp
);
authRouter.post("/verify-email", userAuth, csrfCheck, verifyEmail);
authRouter.get("/is-auth", userAuth, isEmailVerified);

authRouter.post("/send-reset-otp", otpLimiter, sendResetOtp);
authRouter.post("/forgot-password", resetPassword);
authRouter.post("/verify-reset-otp", otpLimiter, verifyResetOtp);

// Token endpoints
authRouter.post("/refresh", csrfCheck, refreshTokens);
authRouter.post("/revoke", csrfCheck, revokeRefreshToken);

// Additional Google OAuth routes
authRouter.get("/google", googleAuthRedirect);
authRouter.get("/google/callback", googleAuthCallback);

export default authRouter;
