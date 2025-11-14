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
      const res = await api.post("/auth/send-verification-otp");
      toast.success(res.data?.message || "Verification email sent");
      // After requesting an OTP, send the user to the verify page so they
      // can enter the code we just emailed them.
      navigate("/verify-email");
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
        <div className="relative group inline-block">
          <div className="w-8 h-8 flex justify-center items-center border-2 border-white rounded-full text-white bg-transparent cursor-pointer">
            {userData?.name?.[0]?.toUpperCase() ||
              userData?.email?.[0]?.toUpperCase() ||
              "U"}
          </div>
          <div className="absolute right-0 top-full mt-0 hidden group-hover:block z-50">
            <ul className="list-none m-0 p-2 text-sm bg-white text-[#1b1835] rounded-md shadow-lg min-w-[160px] cursor-pointer">
              {!userData.isVerified && (
                <li
                  onClick={sendVerificationEmail}
                  className="block py-2 px-3 cursor-pointer rounded"
                >
                  Verify Email
                </li>
              )}

              <li
                onClick={handleLogout}
                className="block py-2 px-3 cursor-pointer rounded"
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
