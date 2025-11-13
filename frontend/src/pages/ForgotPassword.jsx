import React, { useState } from "react";
import { toast } from "react-toastify";

const ForgotPassword = () => {
  const onSubmitHandler = async (e) => {
    e.preventDefault();
    try {
      //backend call to send password reset link to the email
    } catch (error) {
      toast.error(error.message);
    }
  };
  const [email, setEmail] = useState("");
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
