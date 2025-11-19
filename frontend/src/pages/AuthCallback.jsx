import React, { useEffect, useContext } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import axios from "axios";

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setIsLoggedIn, setUserData, getUserData } = useContext(AppContext);

  useEffect(() => {
    (async () => {
      const error = searchParams.get("error");
      if (error) return navigate("/login");

      try {
        const res = await axios.get("/user/profile", { withCredentials: true });
        const user = res?.data?.user;
        if (user) {
          setUserData(user);
          setIsLoggedIn(true);
          return navigate("/", { replace: true });
        }

        await getUserData();
        navigate("/", { replace: true });
      } catch {
        try {
          await getUserData();
          navigate("/", { replace: true });
        } catch {
          navigate("/login");
        }
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h2 className="auth-title">Signing in...</h2>
      </div>
    </div>
  );
};

export default AuthCallback;
