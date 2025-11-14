import React from "react";
import { useContext } from "react";
import { useNavigate } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import api from "../lib/api.js";
import { toast } from "react-toastify";

const VerifyEmail = () => {
  const { getUserData } = useContext(AppContext);

  const inputRefs = React.useRef([]);
  const navigate = useNavigate();

  const handleInputChange = (e, index) => {
    if (e.target.value.length > 0 && index < inputRefs.current.length - 1) {
      inputRefs.current[index + 1].focus();
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Backspace" && e.target.value.length === 0 && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const handlePaste = (e) => {
    const paste = e.clipboardData.getData("text");
    const pasteArray = paste.split("");

    pasteArray.forEach((char, index) => {
      if (index < inputRefs.current.length) {
        inputRefs.current[index].value = char;
      }
    });
  };

  const onSubmitHandler = async (e) => {
    e.preventDefault();
    try {
      const code = inputRefs.current.map((el) => el.value || "").join("");
      if (code.length !== 6) {
        toast.error("Please enter the 6-digit code");
        return;
      }

      await api.post("/auth/verify-email", { otp: code });
      // refresh user info
      await getUserData();
      toast.success("Email verified");
      navigate("/");
    } catch (err) {
      console.error(err);
      toast.error(err?.response?.data?.message || "Verification failed");
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <form onSubmit={onSubmitHandler} className="auth-form">
          <h2 className="auth-title">Verify Email</h2>
          <p className="justify-center text-center mb-4">
            Enter the 6 digit code sent to your email.
          </p>
          <div className="flex justify-between mb-8" onPaste={handlePaste}>
            {Array(6)
              .fill(0)
              .map((_, index) => (
                <input
                  type="text"
                  maxLength="1"
                  key={index}
                  required
                  className="w-12 h-12 text-center text-white bg-[#252055] border-[#1b1835] text-xl rounded-md"
                  ref={(e) => (inputRefs.current[index] = e)}
                  onChange={(e) => handleInputChange(e, index)}
                  onKeyDown={(e) => handleKeyDown(e, index)}
                />
              ))}
          </div>
          <button type="submit" className="btn-primary w-full cursor-pointer">
            Verify Email
          </button>
        </form>
      </div>
    </div>
  );
};

export default VerifyEmail;
