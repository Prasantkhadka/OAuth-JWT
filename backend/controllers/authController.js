import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";

// set cookie options
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "strict",
  maxAge: 24 * 60 * 60 * 1000, // 1 day
};

export const signUp = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    //hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user (use isAccountVerified to match the schema)
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      isAccountVerified: false,
    });
    await newUser.save();

    //asign JWT token
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    //set cookie
    res.cookie("token", token, cookieOptions);

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to OAuth-JWT App",
      text: `Hello ${name},\n\nThank you for signing up for our OAuth-JWT application! We're excited to have you on board.\n\nBest regards,\nOAuth-JWT Team`,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Server error in signUp", error: error.message });
  }
};

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

    // Assign JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    // Set cookie
    res.cookie("token", token, cookieOptions);

    return res.status(200).json({ message: "User signed in successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error in signIn", error: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", cookieOptions);
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
  try {
    return res.status(200).json({ isVerified: req.user.isAccountVerified });
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
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res
      .status(400)
      .json({ message: "Email, OTP, and new password are required" });
  }

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Validate OTP
    if (
      user.resetOtp !== otp ||
      user.resetOtp !== otp ||
      user.resetOtpExpiry < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Check if the new password is same as the old password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res
        .status(400)
        .json({
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
