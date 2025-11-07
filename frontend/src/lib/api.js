import axios from "axios";

// Axios instance configured to use HttpOnly cookies for token storage.
// Backend should set HttpOnly cookies (access/refresh) and enable CORS with credentials.
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:4000",
  withCredentials: true, // important for HttpOnly cookies
});

export default api;
