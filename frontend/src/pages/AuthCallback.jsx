import React, { useEffect, useContext } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import axios from "axios";
import { toast } from "react-toastify";

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setIsLoggedIn, setUserData } = useContext(AppContext);

  useEffect(() => {
    (async () => {
      // If the backend redirected here with an error query, bail out
      const err = searchParams.get("error");
      if (err) {
        toast.error(`OAuth error: ${err}`);
        navigate("/login");
        return;
      }

      try {
        // If a backend URL is configured we likely initiated OAuth against
        // that backend host. In that case request the profile from the
        // backend origin so the browser will include the HttpOnly `token`
        // cookie that the backend set during the OAuth callback.
        const backend = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");
        const profileUrl = backend
          ? `${backend}/api/user/profile`
          : "/api/user/profile";
        const res = await axios.get(profileUrl, { withCredentials: true });
        const user = res?.data?.user;
        if (!user) throw new Error("No user data");

        setUserData(user);
        setIsLoggedIn(true);
        navigate("/", { replace: true });
      } catch (e) {
        console.error("Auth callback failed:", e);
        toast.error(e?.response?.data?.message || "Authentication failed");
        navigate("/login");
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Minimal UI while redirecting
  return (
    <div className="auth-page">
      <div className="auth-card">
        <h2 className="auth-title">Finalizing sign-in...</h2>
        <p className="text-light-200">
          Please wait — finishing authentication.
        </p>
      </div>
    </div>
  );
};

export default AuthCallback;
