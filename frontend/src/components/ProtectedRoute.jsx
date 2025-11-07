import React, { useContext } from "react";
import { Navigate } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";

const ProtectedRoute = ({ children }) => {
  const { isLoggedIn } = useContext(AppContext);
  return isLoggedIn ? children : <Navigate to="/login" replace />;
};

export default ProtectedRoute;
