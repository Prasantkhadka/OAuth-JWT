import React, { useEffect, useContext, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import api from "../lib/api.js";
import { toast } from "react-toastify";

/**
 * AuthCallback component
 *
 * Role in flow:
 * - This page is the frontend landing place for OAuth providers (Google).
 * - The server handles the OAuth redirect, exchanges the code, and sets
 *   HttpOnly cookies (`token`, `refreshToken`). Google callback then
 *   redirects the browser here (front-end) so the app can finalize sign-in.
 * - This component calls GET /api/user/profile which relies on the server-set
 *   `token` cookie. On success it updates AppContext and navigates to the app.
 */
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
          navigate("/login");
          return;
        }

        setStatus("Finalizing sign-in...");

        // Backend should have set an HttpOnly cookie. Request the profile endpoint to obtain user data.
        const res = await api.get("/user/profile");
        const user = res.data && res.data.user;
        if (!user) {
          setStatus("Authentication failed");
          toast.error("Failed to fetch user after OAuth");
          navigate("/login");
          return;
        }

        setUserData(user);
        setIsLoggedIn(true);
        setStatus("Sign-in successful! Redirecting...");
        toast.success("Signed in");
        navigate("/", { replace: true });
      } catch (err) {
        console.error(err);
        setStatus("Authentication failed");
        toast.error(err?.response?.data?.message || "Authentication failed");
        navigate("/login");
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
