import React, { useEffect, useContext } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import axios from "axios";
import { toast } from "react-toastify";

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setIsLoggedIn, setUserData, getUserData } = useContext(AppContext);

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
        // We rely on the proxy; remove unused backend/profileUrl logic.
        const res = await axios.get("/user/profile", { withCredentials: true });
        // Server may return 304 Not Modified (no body) when ETag matches.
        // In that case rely on getUserData() to populate client state via the
        // proxy. Otherwise read user from the response body.
        if (res.status === 304) {
          await getUserData();
          navigate("/", { replace: true });
          return;
        }

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
