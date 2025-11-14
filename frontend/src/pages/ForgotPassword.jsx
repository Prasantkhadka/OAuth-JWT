import React, { useState } from "react";
import { toast } from "react-toastify";
import api from "../lib/api.js";
import { useNavigate } from "react-router-dom";

const ForgotPassword = () => {
  const onSubmitHandler = async (e) => {
    e.preventDefault();
    try {
      await api.post("/auth/send-reset-otp", { email });
      toast.success("Password reset OTP sent (check your email)");
      // redirect to verify OTP page with email in query
      navigate(`/verify-otp?email=${encodeURIComponent(email)}`);
    } catch (error) {
      const msg =
        error?.response?.data?.message || error?.message || "An error occurred";
      toast.error(msg);
    }
  };
  const [email, setEmail] = useState("");
  const navigate = useNavigate();
  return (
    <div className="auth-page">
      <div className="auth-card">
        <form onSubmit={onSubmitHandler} className="auth-form">
          <h2 className="auth-title">Forgot Password</h2>
          <p className="justify-center text-center">
            Enter your email to reset your password.
          </p>

          <input
            className="input-field input-label"
            type="text"
            id="email"
            value={email}
            placeholder="Email"
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <button type="submit" className="btn-primary cursor-pointer mt-4">
            Send Reset OTP
          </button>
        </form>
      </div>
    </div>
  );
};

export default ForgotPassword;
