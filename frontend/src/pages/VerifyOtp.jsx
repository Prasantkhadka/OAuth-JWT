import React from "react";
import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../lib/api.js";

const VerifyOtp = () => {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const emailFromQuery = params.get("email") || "";
  const [email, setEmail] = useState(emailFromQuery);
  const inputRefs = React.useRef([]);
  const [code, setCode] = useState(["", "", "", "", "", ""]);
  const navigate = useNavigate();

  const handleInputChange = (e, index) => {
    const val = e.target.value.replace(/[^0-9]/g, "");
    const next = [...code];
    next[index] = val.slice(-1) || "";
    setCode(next);
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
    const next = [...code];
    pasteArray.slice(0, 6).forEach((char, i) => (next[i] = char));
    setCode(next);
    const last = Math.min(pasteArray.length - 1, 5);
    if (last >= 0 && inputRefs.current[last]) inputRefs.current[last].focus();
  };

  const onSubmitHandler = async (e) => {
    e.preventDefault();
    try {
      const otp = code.join("");
      if (!email) return toast.error("Please provide your email");
      if (otp.length !== 6) return toast.error("Please enter the 6-digit OTP");

      const res = await api.post("/auth/verify-reset-otp", { email, otp });
      const token = res.data?.verificationToken;
      if (!token) return toast.error("Verification failed");
      toast.success("OTP verified. Please choose a new password.");
      navigate(
        `/reset-password?email=${encodeURIComponent(
          email
        )}&token=${encodeURIComponent(token)}`
      );
    } catch (err) {
      console.error(err);
      const msg =
        err?.response?.data?.message || err?.message || "Verification failed";
      toast.error(msg);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <form onSubmit={onSubmitHandler} className="auth-form">
          <h2 className="auth-title">Verify OTP</h2>
          <p className="justify-center text-center mb-4">
            Enter the 6 digit code sent to your email.
          </p>

          <input
            className="input-field input-label mb-4"
            type="email"
            value={email}
            placeholder="Email"
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <div className="flex justify-between mb-8" onPaste={handlePaste}>
            {Array(6)
              .fill(0)
              .map((_, index) => (
                <input
                  type="text"
                  maxLength="1"
                  key={index}
                  className="w-12 h-12 text-center text-white bg-[#252055] border-[#1b1835] text-xl rounded-md"
                  ref={(e) => (inputRefs.current[index] = e)}
                  value={code[index]}
                  onChange={(e) => handleInputChange(e, index)}
                  onKeyDown={(e) => handleKeyDown(e, index)}
                />
              ))}
          </div>

          <button type="submit" className="btn-primary w-full">
            Verify OTP
          </button>
        </form>
      </div>
    </div>
  );
};

export default VerifyOtp;
