import React, { useEffect, useContext, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import api from "../lib/api.js";
import { toast } from "react-toastify";

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setIsLoggedIn, setUserData } = useContext(AppContext);
  const [status, setStatus] = useState("Processing authentication...");

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const error = searchParams.get("error");
        if (error) {
          setStatus("Authentication failed");
          toast.error(`OAuth error: ${error}`);
          return;
        }

        // Placeholder behavior:
        // - In a real integration, the backend would exchange the code and set HttpOnly cookie(s).
        // - Here we simulate finalization and set a mock user in context.

        setStatus("Finalizing sign-in (mock)...");

        // If backend sets HttpOnly cookies, the frontend could call /auth/me to fetch user after redirect:
        // const res = await api.get('/auth/me');
        // setUserData(res.data.user);
        // setIsLoggedIn(true);

        // Simulated success (mock)
        setTimeout(() => {
          setUserData({
            name: "OAuth User",
            email: "user@example.com",
            isVerified: true,
          });
          setIsLoggedIn(true);
          setStatus("Sign-in successful! Redirecting...");
          toast.success("Signed in (mock)");
          navigate("/", { replace: true });
        }, 900);
      } catch (err) {
        console.error(err);
        setStatus("Authentication failed");
        toast.error("Authentication failed");
      }
    };

    handleCallback();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h2 className="auth-title">OAuth callback</h2>
        <p className="text-light-200">{status}</p>
      </div>
    </div>
  );
};

export default AuthCallback;
