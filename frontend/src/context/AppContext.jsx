import { createContext, useState, useEffect } from "react";
import { toast } from "react-toastify";
import api from "../lib/api.js";
import axios from "axios";

export const AppContext = createContext();

export const AppContextProvider = (props) => {
  axios.defaults.withCredentials = true; // send cookies with requests
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userData, setUserData] = useState(null);

  const getAuthState = async () => {
    try {
      const res = await api.get("/auth/is-auth");

      if (res.data.success) {
        setIsLoggedIn(true);
        getUserData();
      }
    } catch (err) {
      toast.error(err.message);
    }
  };

  const getUserData = async () => {
    try {
      const res = await api.get("/auth/me"); // cookie sent automatically
      setUserData(res.data.user);
      setIsLoggedIn(true);
    } catch (err) {
      setUserData(null);
      setIsLoggedIn(false);
      console.error(err);
      toast.error(err.message || "Failed to fetch user data");
    }
  };

  // call getUserData in AppContextProvider useEffect when provider mounts
  useEffect(() => {
    getAuthState();
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
