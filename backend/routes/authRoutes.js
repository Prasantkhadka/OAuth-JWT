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
} from "../controllers/authController.js";
import userAuth from "../middlewares/userAuth.js";

const authRouter = express.Router();

authRouter.post("/signup", signUp);
authRouter.post("/login", signIn);
authRouter.post("/logout", logout);

authRouter.post("/send-verification-otp", userAuth, sendVerificationOtp);
authRouter.post("/verify-email", userAuth, verifyEmail);
authRouter.get("/is-email-verified", userAuth, isEmailVerified);

authRouter.post("/send-reset-otp", sendResetOtp);
authRouter.post("/forgot-password", resetPassword);

export default authRouter;
