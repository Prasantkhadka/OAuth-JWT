import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import dotenv from "dotenv";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
connectDB();

// When running behind Vercel (or other proxies) enable trust proxy so that
// secure cookies (Secure: true) and other proxy-aware settings work correctly.
// This is important when Vercel routes traffic through its proxy layer.
app.set("trust proxy", 1);

// Allowed origin for CORS. Should be set in Vercel environment variables for
// the backend project (FRONTEND_URL = https://o-auth-jwt.vercel.app).
const allowedOrigins = process.env.FRONTEND_URL || "http://localhost:5174";
console.log("CORS allowed origin:", allowedOrigins);

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: allowedOrigins, credentials: true }));

// Sample route to check server status
app.get("/", (req, res) => {
  res.send("OAuth-JWT Backend is running");
});

// Debug helper: return cookies seen by the server for the incoming request.
// Useful to verify whether the browser is sending cookies through the Vercel
// proxy. Keep this endpoint simple and remove or restrict it in production.
app.get("/api/debug/cookies", (req, res) => {
  try {
    return res.status(200).json({ cookies: req.cookies || {} });
  } catch (err) {
    return res.status(500).json({ error: "Unable to read cookies" });
  }
});

// Api routes
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running..`);
});
