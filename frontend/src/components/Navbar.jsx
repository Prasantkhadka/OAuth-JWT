import React, { useContext } from "react";
import { AppContext } from "../context/AppContext.jsx";
import { Link, useNavigate, useLocation } from "react-router-dom";
import api from "../lib/api.js";
import { toast } from "react-toastify";

const Navbar = () => {
  const { userData, setUserData, setIsLoggedIn } = useContext(AppContext);
  const navigate = useNavigate();
  const location = useLocation();

  const sendVerificationEmail = async () => {
    try {
      const res = await api.post("/auth/send-verification");
      toast.success(res.data?.message || "Verification email sent");
    } catch (err) {
      console.error(err);
      toast.error(
        err?.response?.data?.message || "Failed to send verification email"
      );
    }
  };

  const handleLogout = async () => {
    try {
      await api.post("/auth/logout");
      // clear client state
      setUserData(null);
      setIsLoggedIn(false);
      toast.success("Logged out");
      navigate("/login");
    } catch (err) {
      console.error(err);
      toast.error("Logout failed");
    }
  };

  return (
    <div className="w-full flex items-center justify-between p-6 bg-transparent backdrop-blur-xl border-b border-[#2c2946]">
      <div className="text-white font-bold text-xl">
        <Link to="/">MyApp</Link>
      </div>

      {userData ? (
        <div className="relative group">
          <div className="w-8 h-8 flex justify-center items-center rounded-full text-white bg-transparent">
            {userData?.name?.[0]?.toUpperCase() ||
              userData?.email?.[0]?.toUpperCase() ||
              "U"}
          </div>
          <div className="absolute hidden group-hover:block top-0 right-0 z-10 cursor-pointer">
            <ul className="list-none m-0 p-2 text-sm">
              {!userData.isVerified && (
                <li
                  onClick={sendVerificationEmail}
                  className="py-1 px-2 hover:bg-light-700 cursor-pointer"
                >
                  Verify Email
                </li>
              )}

              <li
                onClick={handleLogout}
                className="py-1 px-2 hover:bg-light-700 cursor-pointer"
              >
                Logout
              </li>
            </ul>
          </div>
        </div>
      ) : (
        <>
          {location.pathname !== "/login" && (
            <Link to="/login" className="btn-primary text-sm">
              Login
            </Link>
          )}
        </>
      )}
    </div>
  );
};

export default Navbar;
