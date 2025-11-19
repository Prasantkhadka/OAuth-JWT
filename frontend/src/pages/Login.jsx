import { useState, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { AppContext } from "../context/AppContext.jsx";
import axios from "axios";
import { FcGoogle } from "react-icons/fc";
import { toast } from "react-toastify";

const Login = () => {
  const navigate = useNavigate();
  const { getUserData } = useContext(AppContext);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [state, setState] = useState("Sign In");

  const onSubmitHandler = async (e) => {
    try {
      e.preventDefault();

      if (state === "Sign In") {
        await axios.post(
          "/api/auth/login",
          { email, password },
          { withCredentials: true }
        );
        // backend sets HttpOnly cookie; fetch profile to populate client state
        await getUserData();
        navigate("/");
      } else {
        await axios.post(
          "/api/auth/signup",
          { name, email, password },
          { withCredentials: true }
        );
        await getUserData();
        navigate("/");
      }
    } catch (error) {
      console.error(error);
      const msg =
        error?.response?.data?.message || error?.message || "An error occurred";
      toast.error(msg);
    }
  };

  // Prefer a configured backend URL so the oauth_state cookie is set on the
  // backend domain (ensuring Google's redirect back to backend includes it).
  // Fall back to the proxy path for local dev when no backend URL is provided.
  const googleHref = (() => {
    const backend = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");
    return backend ? `${backend}/api/auth/google` : "/api/auth/google";
  })();

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
                    className="input-field"
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
                  className="input-field"
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
                  className="input-field"
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

          <a
            href={googleHref}
            className="btn-secondary w-full cursor-pointer hover:shadow-lg inline-flex items-center justify-center gap-2"
          >
            <FcGoogle className="w-5 h-5" />
            Google
          </a>

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
