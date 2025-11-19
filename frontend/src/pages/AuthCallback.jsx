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
        // Ask the backend for the profile. axios.defaults.baseURL is set
        // in AppContext; this will call `/api/user/profile` (via proxy)
        // or the configured backend depending on env.
        const res = await axios.get("/user/profile", { withCredentials: true });
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
