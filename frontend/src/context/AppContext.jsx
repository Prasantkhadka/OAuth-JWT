import { createContext, useState, useEffect } from "react";
import { toast } from "react-toastify";
import axios from "axios";

export const AppContext = createContext();

export const AppContextProvider = (props) => {
  // Configure axios to use the relative /api base (works with Vercel proxy)
  const useExternal = import.meta.env.VITE_USE_EXTERNAL_API === "true";
  const envUrl = import.meta.env.VITE_API_URL || "";
  // configure axios once on mount
  useEffect(() => {
    axios.defaults.baseURL =
      useExternal && envUrl ? `${envUrl.replace(/\/$/, "")}/api` : "/api";
    axios.defaults.withCredentials = true; // send cookies with requests

    // Attach CSRF header from readable cookie for state-changing requests
    const id = axios.interceptors.request.use(
      (config) => {
        try {
          const match = document.cookie.match(
            new RegExp("(^|;)\\s*csrfToken=([^;]+)")
          );
          const csrf = match ? decodeURIComponent(match[2]) : null;
          if (csrf) {
            if (!config.headers) config.headers = {};
            config.headers["X-CSRF-Token"] = csrf;
          }
        } catch (err) {
          // ignore during SSR or if cookie parsing fails
        }
        return config;
      },
      (err) => Promise.reject(err)
    );

    return () => axios.interceptors.request.eject(id);
  }, []);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userData, setUserData] = useState(null);

  const getUserData = async () => {
    try {
      const res = await axios.get("/user/profile", { withCredentials: true }); // ensure cookies are sent
      setUserData(res.data.user);
      setIsLoggedIn(true);
    } catch (err) {
      // If 401: user is unauthenticated — don't spam the user with an error toast.
      if (err?.response?.status === 401) {
        setUserData(null);
        setIsLoggedIn(false);
        return;
      }

      // Other errors are worth surfacing
      setUserData(null);
      setIsLoggedIn(false);
      console.error(err);
      toast.error(
        err?.response?.data?.message ||
          err.message ||
          "Failed to fetch user data"
      );
    }
  };

  // call getUserData in AppContextProvider useEffect when provider mounts
  useEffect(() => {
    getUserData();
  }, []);

  const value = {
    isLoggedIn,
    setIsLoggedIn,
    userData,
    setUserData,
    getUserData,
  };

  return (
    <AppContext.Provider value={value}>{props.children}</AppContext.Provider>
  );
};
