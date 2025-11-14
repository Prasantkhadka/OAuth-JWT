import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../lib/api.js";

const ResetPassword = () => {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const tokenFromQuery = params.get("token") || "";
  const emailFromQuery = params.get("email") || "";

  const [email, setEmail] = useState(emailFromQuery);
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const navigate = useNavigate();

  const inputRefs = React.useRef([]);

  const handleInputChange = (e, index) => {
    const val = e.target.value.replace(/[^0-9]/g, "");
    const next = [...otp];
    next[index] = val.slice(-1) || "";
    setOtp(next);
    if (val && index < inputRefs.current.length - 1) {
      inputRefs.current[index + 1].focus();
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Backspace" && e.target.value.length === 0 && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const handlePaste = (e) => {
    const paste = e.clipboardData.getData("text").trim();
    const pasteArray = paste.split("").filter((c) => /[0-9]/.test(c));
    const next = [...otp];
    pasteArray.slice(0, 6).forEach((char, i) => (next[i] = char));
    setOtp(next);
    // focus last pasted
    const last = Math.min(pasteArray.length - 1, 5);
    if (last >= 0 && inputRefs.current[last]) inputRefs.current[last].focus();
  };

  const onSubmitHandler = async (e) => {
    e.preventDefault();
    try {
      // if a verification token was passed via query params, use it and skip OTP inputs
      if (tokenFromQuery) {
        if (!email) return toast.error("Email missing");
        if (!newPassword || newPassword.length < 6)
          return toast.error(
            "Please enter a password with at least 6 characters"
          );
        if (newPassword !== confirmPassword)
          return toast.error("Password and confirm password do not match");

        await api.post("/auth/forgot-password", {
          email,
          newPassword,
          verificationToken: tokenFromQuery,
        });

        toast.success("Password reset successfully. Please login.");
        navigate("/login");
        return;
      }

      // fallback: OTP flow
      const code = otp.join("");
      if (!email) return toast.error("Please enter your email");
      if (code.length !== 6) return toast.error("Please enter the 6-digit OTP");
      if (!newPassword || newPassword.length < 6)
        return toast.error(
          "Please enter a password with at least 6 characters"
        );
      if (newPassword !== confirmPassword)
        return toast.error("Password and confirm password do not match");

      await api.post("/auth/forgot-password", {
        email,
        otp: code,
        newPassword,
      });

      toast.success("Password reset successfully. Please login.");
      navigate("/login");
    } catch (err) {
      console.error(err);
      const msg =
        err?.response?.data?.message ||
        err?.message ||
        "Failed to reset password";
      toast.error(msg);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <form onSubmit={onSubmitHandler} className="auth-form">
          <h2 className="auth-title">Reset Password</h2>
          <p className="justify-center text-center mb-4">
            Enter the OTP sent to your email and choose a new password.
          </p>

          <input
            className="input-field input-label mb-4"
            type="email"
            id="email"
            value={email}
            placeholder="Email"
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          {tokenFromQuery ? (
            <>
              <input
                className="input-field input-label mb-4"
                type="password"
                id="newPassword"
                value={newPassword}
                placeholder="New password (min 6 chars)"
                onChange={(e) => setNewPassword(e.target.value)}
                required
              />
              <input
                className="input-field input-label mb-4"
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                placeholder="Confirm new password"
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
              <button
                type="submit"
                className="btn-primary cursor-pointer w-full"
              >
                Reset Password
              </button>
            </>
          ) : (
            <>
              <div className="flex justify-between mb-6" onPaste={handlePaste}>
                {Array(6)
                  .fill(0)
                  .map((_, index) => (
                    <input
                      key={index}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      className="w-12 h-12 text-center text-white bg-[#252055] border-[#1b1835] text-xl rounded-md"
                      ref={(el) => (inputRefs.current[index] = el)}
                      value={otp[index]}
                      onChange={(e) => handleInputChange(e, index)}
                      onKeyDown={(e) => handleKeyDown(e, index)}
                    />
                  ))}
              </div>

              <input
                className="input-field input-label mb-4"
                type="password"
                id="newPassword"
                value={newPassword}
                placeholder="New password (min 6 chars)"
                onChange={(e) => setNewPassword(e.target.value)}
                required
              />
              <input
                className="input-field input-label mb-4"
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                placeholder="Confirm new password"
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />

              <button
                type="submit"
                className="btn-primary cursor-pointer w-full"
              >
                Reset Password
              </button>
            </>
          )}
        </form>
      </div>
    </div>
  );
};

export default ResetPassword;
