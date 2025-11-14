import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

// Google OAuth configuration
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";

// Access / refresh token cookie options
const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRES || "15m"; // used for signing
const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRES || "7d";

const accessCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "strict",
  // maxAge in ms; parse short/long defaults
  maxAge: 15 * 60 * 1000, // 15 minutes
};

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

// CSRF cookie for double-submit protection (not httpOnly so client JS can read and send it)
const csrfCookieOptions = {
  httpOnly: false,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

// Legacy OAuth cookie options (used only during Google OAuth redirect flow)
const oauthCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
  maxAge: 24 * 60 * 60 * 1000,
};

/* Utility helpers to generate and protect tokens
   - generateAccessToken(userId): returns a short-lived JWT used for API access.
     This token is intended to be stored as an HttpOnly cookie named `token`.
   - generateRefreshToken(userId): returns a longer-lived JWT used to refresh
     access tokens. The raw refresh token is sent to the client as an HttpOnly
     cookie named `refreshToken`, but only a hashed form is stored in the DB.
   - hashToken(token): computes a SHA-256 hex digest of a token. We store and
     compare hashes in the database to avoid persisting raw, usable refresh
     tokens. If the DB is leaked, attackers get only hashes, not valid tokens.
   - genCsrfToken(): generates a random token that is set in a readable cookie
     `csrfToken` so the frontend can perform the double-submit CSRF check.
*/
function generateAccessToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: accessTokenExpiry,
  });
}

function generateRefreshToken(userId) {
  // use a dedicated secret for refresh tokens if provided
  const secret = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET;
  return jwt.sign({ id: userId }, secret, { expiresIn: refreshTokenExpiry });
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function genCsrfToken() {
  return crypto.randomBytes(24).toString("hex");
}

export const signUp = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(409)
        .json({ message: "User already exists, Please login" });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      isAccountVerified: false,
    });
    await newUser.save();

    // issue tokens
    // - accessToken: used for API auth (short-lived)
    // - refreshToken: used to rotate and obtain new access tokens (long-lived)
    const accessToken = generateAccessToken(newUser._id);
    const refreshToken = generateRefreshToken(newUser._id);

    // store hashed refresh token on user (protect DB in case of leak)
    const hashed = hashToken(refreshToken);
    newUser.refreshTokens = [...(newUser.refreshTokens || []), hashed];
    await newUser.save();

    // set cookies (raw tokens are sent to client cookies)
    res.cookie("token", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);
    // set csrf token for double-submit pattern
    const csrf = genCsrfToken();
    res.cookie("csrfToken", csrf, csrfCookieOptions);

    // send welcome email (best-effort)
    try {
      const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: email,
        subject: "Welcome to OAuth-JWT App",
        text: `Hello ${name},\n\nThank you for signing up for our OAuth-JWT application! We're excited to have you on board.\n\nBest regards,\nOAuth-JWT Team`,
      };
      await transporter.sendMail(mailOptions);
    } catch (mailErr) {
      console.error(
        "Failed to send welcome email:",
        mailErr?.message || mailErr
      );
    }

    return res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in signUp", error: error.message });
  }
};

/**
 * signIn - authenticate a user by email + password
 *
 * Steps:
 *  1. Validate email and password presence.
 *  2. Find user and compare bcrypt password.
 *  3. Issue access & refresh tokens. Store only a hashed refresh token in DB
 *     and send raw tokens to the client as HttpOnly cookies.
 *  4. Set a readable `csrfToken` cookie used by the frontend for double-submit
 *     CSRF protection. Frontend should send it in `X-CSRF-Token` header.
 */
export const signIn = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // issue tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // persist hashed refresh token
    const hashed = hashToken(refreshToken);
    user.refreshTokens = [...(user.refreshTokens || []), hashed];
    await user.save();

    // set cookies
    res.cookie("token", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);
    // set csrf token
    const csrf = genCsrfToken();
    res.cookie("csrfToken", csrf, csrfCookieOptions);

    return res.status(200).json({ message: "User signed in successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in signIn", error: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    // attempt to remove refresh token from DB (if provided in cookie)
    try {
      const refreshToken = req.cookies && req.cookies.refreshToken;
      if (refreshToken) {
        const secret =
          process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET;
        // verify the refresh token to extract user id
        const decoded = jwt.verify(refreshToken, secret);
        if (decoded && decoded.id) {
          const user = await User.findById(decoded.id);
          if (user && user.refreshTokens && user.refreshTokens.length) {
            // refresh tokens are stored as hashed values in DB
            // compute hash of the presented token and remove it from DB
            // so that this specific refresh token can no longer be used
            const hashed = hashToken(refreshToken);
            user.refreshTokens = user.refreshTokens.filter((t) => t !== hashed);
            await user.save();
          }
        }
      }
    } catch (e) {
      // ignore token verify errors during logout — still attempt to clear cookies
    }

    // clear cookies on client side so browser no longer sends them
    res.clearCookie("token", accessCookieOptions);
    res.clearCookie("refreshToken", refreshCookieOptions);
    return res.status(200).json({ message: "User logged out successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in logout", error: error.message });
  }
};

export const sendVerificationOtp = async (req, res) => {
  const userId = req.user.id;
  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  try {
    // Find user by ID
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isAccountVerified) {
      return res.status(400).json({ message: "User is already verified" });
    }

    // Generate a 6-digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // Save OTP and its expiry time (10 minutes) to user document
    user.verifyOtp = otp;
    user.verifyOtpExpiry = Date.now() + 10 * 60 * 1000;
    await user.save();

    // Send OTP via email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP for account verification is: ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    return res
      .status(200)
      .json({ message: "Verification OTP sent successfully" });
  } catch (error) {
    return res.status(500).json({
      message: "Server error in sendVerificationOtp",
      error: error.message,
    });
  }
};

/*
  sendVerificationOtp
  - Protected endpoint (requires a valid user via `userAuth`).
  - Generates a 6-digit OTP, stores it on the user with a short expiry, and
    sends the OTP to the user's registered email address for account verification.
  - This function deliberately keeps the email send step best-effort and logs
    failures rather than failing user creation flows.
*/

// Exchange refresh token for new access + refresh tokens (rotation)
export const refreshTokens = async (req, res) => {
  /*
    refreshTokens - exchange a valid refresh token for a new access + refresh pair

    Flow:
    1. Read refresh token from cookie.
    2. Verify the JWT to get user id (ensures token integrity/signature).
    3. Hash the presented refresh token and ensure it exists in the user's
       stored `refreshTokens` (prevents reuse of revoked tokens).
    4. Rotate: issue new access & refresh tokens, replace the old hashed value
       with the new hashed refresh token in DB, and set cookies.

    Security: rotation reduces the window where a stolen refresh token is
    useful. We store only hashed refresh tokens so DB leaks don't reveal raw
    tokens.
  */
  try {
    const refreshToken = req.cookies && req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const secret = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET;
    let payload;
    try {
      payload = jwt.verify(refreshToken, secret);
    } catch (err) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const user = await User.findById(payload.id);
    if (!user)
      return res.status(401).json({ message: "Invalid refresh token" });

    // ensure the refresh token is one we issued and haven't revoked
    // ensure the refresh token is one we issued and haven't revoked
    const incomingHashed = hashToken(refreshToken);
    if (!user.refreshTokens || !user.refreshTokens.includes(incomingHashed)) {
      return res.status(401).json({ message: "Refresh token revoked" });
    }

    // rotation: generate new tokens and replace the old refresh token
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // replace old token hash with new one (we store hashed tokens in DB)
    user.refreshTokens = user.refreshTokens.filter((t) => t !== incomingHashed);
    user.refreshTokens.push(hashToken(newRefreshToken));
    await user.save();

    // set cookies
    res.cookie("token", newAccessToken, accessCookieOptions);
    res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);

    return res.status(200).json({ message: "Tokens refreshed" });
  } catch (err) {
    console.error("Error in refreshTokens:", err?.message || err);
    return res.status(500).json({ message: "Server error in refreshTokens" });
  }
};

// Revoke refresh token (logout-like). Accept cookie or body.token
export const revokeRefreshToken = async (req, res) => {
  try {
    /*
      revokeRefreshToken - remove a refresh token from the user's stored set

      - Accepts either the cookie refreshToken or a token in the request body.
      - Verifies the JWT, locates the user, hashes the presented token, and
        removes the matching hash from `user.refreshTokens` so that token is
        effectively revoked.
      - Always clears cookies on the response so the client loses its tokens.
    */
    const tokenToRevoke = req.cookies?.refreshToken || req.body?.token;
    if (!tokenToRevoke) {
      // clear cookies anyway
      res.clearCookie("token", accessCookieOptions);
      res.clearCookie("refreshToken", refreshCookieOptions);
      return res.status(200).json({ message: "Tokens cleared" });
    }

    const secret = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET;
    try {
      const payload = jwt.verify(tokenToRevoke, secret);
      const user = await User.findById(payload.id);
      if (user && user.refreshTokens && user.refreshTokens.length) {
        // remove hashed token
        const hashed = hashToken(tokenToRevoke);
        user.refreshTokens = user.refreshTokens.filter((t) => t !== hashed);
        await user.save();
      }
    } catch (err) {
      // ignore invalid token but still clear cookies
    }

    res.clearCookie("token", accessCookieOptions);
    res.clearCookie("refreshToken", refreshCookieOptions);
    return res.status(200).json({ message: "Refresh token revoked" });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Server error in revokeRefreshToken" });
  }
};

export const verifyEmail = async (req, res) => {
  const { otp } = req.body;
  const userId = req.user.id;

  if (!otp) {
    return res.status(400).json({ message: "OTP is required" });
  }

  try {
    // Find user by ID
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.verifyOtp || user.verifyOtp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (user.verifyOtpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP has expired" });
    }

    // Mark user as verified
    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpiry = 0;
    await user.save();

    return res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in verifyEmail", error: error.message });
  }
};

// Check if the email is verified
export const isEmailVerified = async (req, res) => {
  /*
    isEmailVerified - helper endpoint used by the frontend to check whether
    the authenticated user's email has been verified. Returns `{ isVerified: true|false }`.
    The route expects `userAuth` middleware to populate `req.user`.
  */
  try {
    const userId = req.user && req.user.id;
    if (!userId) return res.status(401).json({ message: "Not authorized" });
    const user = await User.findById(userId).select("isAccountVerified");
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.status(200).json({ isVerified: !!user.isAccountVerified });
  } catch (error) {
    return res.status(500).json({
      message: "Server error in isEmailVerified",
      error: error.message,
    });
  }
};

// Send password reset OTP
export const sendResetOtp = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate a 6-digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // Save OTP and its expiry time (10 minutes) to user document
    user.resetOtp = otp;
    user.resetOtpExpiry = Date.now() + 10 * 60 * 1000;
    await user.save();

    // Send OTP via email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    return res
      .status(200)
      .json({ message: "Password reset OTP sent successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in sendResetOtp", error: error.message });
  }
};

// Reset password using OTP
export const resetPassword = async (req, res) => {
  /*
    resetPassword - performs a password reset for a user.

    Behavior:
    - Accepts `email` + `newPassword` plus either an `otp` (one-time code)
      or a `verificationToken` (JWT returned by verifyResetOtp).
    - If `verificationToken` provided: validate it matches the user's email.
    - Otherwise validate the provided OTP and expiry stored on the user.
    - Ensure the new password differs from the old one, hash it, and save.
    - Clears reset OTP fields after successful change.
  */
  const { email, otp, newPassword, verificationToken } = req.body;

  if (!email || !newPassword) {
    return res
      .status(400)
      .json({ message: "Email and new password are required" });
  }

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // If a verificationToken is provided (from verify-reset-otp), validate it
    if (verificationToken) {
      try {
        const secret = process.env.RESET_TOKEN_SECRET || process.env.JWT_SECRET;
        const payload = jwt.verify(verificationToken, secret);
        // ensure token matches the user
        if (!payload || !payload.email || payload.email !== user.email) {
          return res
            .status(401)
            .json({ message: "Invalid verification token" });
        }
      } catch (err) {
        return res
          .status(401)
          .json({ message: "Invalid or expired verification token" });
      }
    } else {
      // fallback to OTP validation if no verification token
      if (!otp) {
        return res.status(400).json({ message: "OTP is required" });
      }
      if (user.resetOtp !== otp || user.resetOtpExpiry < Date.now()) {
        return res.status(400).json({ message: "Invalid or expired OTP" });
      }
    }

    // Check if the new password is same as the old password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        message: "New password must be different from the old password",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpiry = 0;
    await user.save();

    return res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in resetPassword", error: error.message });
  }
};

// Verify reset OTP and return a short-lived verification token for resetting password
export const verifyResetOtp = async (req, res) => {
  /*
    verifyResetOtp - validate a password-reset OTP and return a short-lived
    verification JWT that the frontend can use to call `resetPassword` safely.

    Flow:
    - Validate email & OTP provided in body.
    - Check stored `resetOtp` and expiry.
    - If valid, sign a short-lived verification token (contains id + email)
      and return it to the client. The client should send this token when
      posting the new password to `resetPassword` to avoid re-sending an OTP.
  */
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.resetOtp !== otp || user.resetOtpExpiry < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // generate a short-lived verification token
    const secret = process.env.RESET_TOKEN_SECRET || process.env.JWT_SECRET;
    const token = jwt.sign({ id: user._id, email: user.email }, secret, {
      expiresIn: process.env.RESET_TOKEN_EXPIRES || "15m",
    });

    return res
      .status(200)
      .json({ message: "OTP verified", verificationToken: token });
  } catch (err) {
    return res.status(500).json({ message: "Server error in verifyResetOtp" });
  }
};

// Google OAuth Redirect
const oauth2Client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

function genState(len = 24) {
  return [...Array(len)]
    .map(() => Math.floor(Math.random() * 36).toString(36))
    .join("");
}

// Add this function to open the consent page
/**
 * googleAuthRedirect - start the Google OAuth2 authorization code flow
 *
 * - Generates a random `state` value and stores it in a short-lived cookie
 *   to protect against CSRF during the OAuth callback.
 * - Redirects the user to Google's consent page requesting `openid profile email`.
 */
export const googleAuthRedirect = (req, res) => {
  const state = genState(24);
  // store state in cookie for validation on callback (short-lived)
  res.cookie("oauth_state", state, {
    maxAge: 5 * 60 * 1000,
    httpOnly: false,
    sameSite: "lax",
  });

  const url = oauth2Client.generateAuthUrl({
    access_type: "offline", // request refresh_token
    scope: ["openid", "profile", "email"],
    prompt: "consent", // to always get refresh_token on first consent
    state,
  });

  return res.redirect(url);
};

/**
 * googleAuthCallback - handle Google's OAuth2 callback
 *
 * Flow:
 *  1. Verify `state` cookie matches query `state` to mitigate CSRF.
 *  2. Exchange the authorization code for tokens and verify the id_token.
 *  3. Find or create a local user record for the Google account email.
 *  4. Issue access & refresh tokens and persist only the hashed refresh token.
 *  5. Set cookies and redirect to frontend `/auth/callback` which finalizes
 *     the flow (frontend can read cookies and proceed).
 */
export const googleAuthCallback = async (req, res) => {
  try {
    const { code, state } = req.query;
    const savedState = req.cookies && req.cookies.oauth_state;

    if (!code) {
      return res.status(400).send("Missing code");
    }

    if (!state || !savedState || state !== savedState) {
      return res.status(400).send("Invalid state (possible CSRF)");
    }

    // Exchange code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    // tokens.id_token contains the JWT from Google. Verify it:
    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: CLIENT_ID,
    });
    const payload = ticket.getPayload();

    const email = payload.email;
    const name = payload.name || payload.given_name || "Google User";
    const picture = payload.picture || "";

    if (!email) {
      return res.status(400).send("Google account has no email");
    }

    // Find or create user
    let user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // create a local user record for this Google account
      // the schema requires a password; create a random one and hash it so
      // validation passes. The password won't be used for OAuth logins.
      const randomPassword =
        Math.random().toString(36).slice(-10) + Date.now().toString(36);
      const hashedPwd = await bcrypt.hash(randomPassword, 10);

      user = new User({
        name,
        email: email.toLowerCase(),
        password: hashedPwd,
        isAccountVerified: true, // google-verified email
      });
      await user.save();
    } else {
      // Optionally update name/picture if missing
      if (!user.name && name) user.name = name;
      if (!user.isAccountVerified) user.isAccountVerified = true;
      await user.save();
    }

    // issue access + refresh tokens (persist refresh token)
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    // store hashed refresh token
    user.refreshTokens = [
      ...(user.refreshTokens || []),
      hashToken(refreshToken),
    ];
    await user.save();

    // set cookies (use oauth-specific cookie options for the access token)
    res.cookie("token", accessToken, oauthCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

    // clear the oauth_state cookie
    res.clearCookie("oauth_state");

    // Redirect user to frontend callback route which finalizes the flow
    return res.redirect(`${FRONTEND_URL.replace(/\/$/, "")}/auth/callback`);
  } catch (err) {
    // Log detailed error information to help debugging
    try {
      console.error("Google OAuth callback error:", err?.message || err);
      if (err?.response) {
        console.error("OAuth token exchange/verify response:", err.response);
      }
      if (err?.stack) console.error(err.stack);
    } catch (logErr) {
      console.error("Error while logging OAuth error:", logErr);
    }

    // Redirect to frontend callback route with an error flag so the frontend
    // can show a friendly message and avoid rendering the backend error page.
    const errMsg = encodeURIComponent(err?.message || "Authentication failed");
    return res.redirect(
      `${FRONTEND_URL.replace(/\/$/, "")}/auth/callback?error=${errMsg}`
    );
  }
};
