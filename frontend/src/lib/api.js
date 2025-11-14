import axios from "axios";

// Helper to read a cookie value in the browser
function getCookie(name) {
  if (typeof document === "undefined") return null;
  const pairs = document.cookie ? document.cookie.split("; ") : [];
  for (let i = 0; i < pairs.length; i++) {
    const [k, v] = pairs[i].split("=");
    if (k === name) return decodeURIComponent(v || "");
  }
  return null;
}

// Axios instance configured to use HttpOnly cookies for token storage.
// Backend should set HttpOnly cookies (access/refresh) and enable CORS with credentials.
// Base URL should point at the backend root; routes are mounted under /api on the server.
const base = (import.meta.env.VITE_API_URL || "http://localhost:4000").replace(
  /\/$/,
  ""
);
const api = axios.create({
  baseURL: `${base}/api`,
  withCredentials: true, // important for HttpOnly cookies
});

// Add a request interceptor to include the CSRF token (double-submit) when present.
// The server sets a readable cookie named `csrfToken` during auth; frontend must
// send that value in the X-CSRF-Token header for state-changing endpoints.
api.interceptors.request.use(
  (config) => {
    try {
      const csrf = getCookie("csrfToken");
      if (csrf) {
        if (!config.headers) config.headers = {};
        config.headers["X-CSRF-Token"] = csrf;
      }
    } catch {
      // ignore; if document isn't available or parsing fails, requests continue
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export default api;
