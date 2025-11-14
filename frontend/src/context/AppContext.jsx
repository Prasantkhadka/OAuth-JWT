import { createContext, useState, useEffect } from "react";
import { toast } from "react-toastify";
import api from "../lib/api.js";
import axios from "axios";

export const AppContext = createContext();

export const AppContextProvider = (props) => {
  axios.defaults.withCredentials = true; // send cookies with requests
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userData, setUserData] = useState(null);

  const getUserData = async () => {
    try {
      const res = await api.get("/user/profile"); // cookie sent automatically
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
