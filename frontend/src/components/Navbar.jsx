import React, { useContext } from "react";
import { AppContext } from "../context/AppContext.jsx";
import { Link, useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import { toast } from "react-toastify";

const Navbar = () => {
  const { userData, setUserData, setIsLoggedIn } = useContext(AppContext);
  const navigate = useNavigate();
  const location = useLocation();

  const sendVerificationEmail = async () => {
    try {
      const res = await axios.post("/auth/send-verification-otp", null, {
        withCredentials: true,
      });
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
      await axios.post("/auth/logout", null, { withCredentials: true });
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
        <div className="relative inline-block group focus-within:outline-none">
          <button
            type="button"
            className="w-8 h-8 flex justify-center items-center border-2 border-white rounded-full text-white bg-transparent cursor-pointer focus:outline-none focus:ring-2 focus:ring-white/60"
            aria-haspopup="true"
          >
            {userData?.name?.[0]?.toUpperCase() ||
              userData?.email?.[0]?.toUpperCase() ||
              "U"}
          </button>
          <div className="absolute right-0 top-full mt-0 z-50 hidden group-hover:block group-focus-within:block">
            <ul className="list-none m-0 p-2 text-sm bg-white text-[#1b1835] rounded-md shadow-lg min-w-[160px] cursor-pointer">
              {!userData.isVerified && (
                <li
                  onClick={sendVerificationEmail}
                  className="block py-2 px-3 cursor-pointer rounded hover:bg-gray-100"
                >
                  Verify Email
                </li>
              )}

              <li
                onClick={handleLogout}
                className="block py-2 px-3 cursor-pointer rounded hover:bg-gray-100"
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
