import { useState, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import { FcGoogle } from "react-icons/fc";
import { toast } from "react-toastify";

const Login = () => {
  const navigate = useNavigate();
  const { setIsLoggedIn, setUserData } = useContext(AppContext);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [state, setState] = useState("Sign In");

  const onSubmitHandler = async (e) => {
    try {
      e.preventDefault();

      if (state === "Sign In") {
        // TODO: call your backend endpoint to log in the user
      } else {
        // TODO: call your backend endpoint to sign up the user
      }
    } catch (error) {
      console.log(error);
      toast.error(error.message);
    }
  };

  return (
    <div>
      <div className="auth-page">
        <div className="auth-card">
          <h2 className="auth-title">
            {state === "Sign Up" ? "Create Account" : "Sign In"}
          </h2>

          <form onSubmit={onSubmitHandler} className="auth-form">
            <div className="auth-card">
              {state === "Sign Up" && (
                <div>
                  <label className="input-label px-2" htmlFor="name">
                    Name
                  </label>
                  <input
                    className="input-field "
                    type="text"
                    id="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                  />
                </div>
              )}
              <div>
                <label className="input-label px-2" htmlFor="email">
                  Email
                </label>
                <input
                  className="input-field "
                  type="text"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="input-label px-2" htmlFor="password">
                  Password
                </label>
                <input
                  className="input-field "
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <p>
                Forgot your password?{" "}
                <span
                  className="link-text"
                  onClick={() => navigate("/forgot-password")}
                >
                  Reset Password
                </span>
              </p>
              <button
                type="submit"
                className="btn-primary w-full mt-4 cursor-pointer"
              >
                {state === "Sign Up" ? "Create Account" : "Sign In"}
              </button>
            </div>
          </form>
          <div className="divider">or continue with</div>
          <button className="btn-secondary w-full cursor-pointer hover:shadow-lg">
            <FcGoogle className="w-5 h-5" />
            Google
          </button>
          <p className="text-center mt-4">
            {state === "Sign Up"
              ? "Already have an account? "
              : "Don't have an account? "}
            <span
              className="link-text"
              onClick={() =>
                setState(state === "Sign Up" ? "Sign In" : "Sign Up")
              }
            >
              {state === "Sign Up" ? "Sign In" : "Create Account"}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
