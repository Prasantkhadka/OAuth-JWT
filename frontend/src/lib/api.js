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
// When deployed on Vercel we prefer using a rewrite/proxy so frontend calls
// relative paths (/api/...) and Vercel forwards them to the backend. This
// avoids cross-site cookie issues. If VITE_API_URL is set, it will be used
// (useful for local dev or non-proxied setups).
// Prefer the relative proxy (/api) by default (works with Vercel rewrites).
// Only use an external backend URL when VITE_USE_EXTERNAL_API === 'true'
// to avoid unintentionally making cross-site requests which can block cookies.
const envUrl = import.meta.env.VITE_API_URL || "";
const useExternal = import.meta.env.VITE_USE_EXTERNAL_API === "true";
const configuredBackend = useExternal ? envUrl.replace(/\/$/, "") : "";
const apiBase = configuredBackend ? `${configuredBackend}/api` : "/api";
const api = axios.create({
  baseURL: apiBase,
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
