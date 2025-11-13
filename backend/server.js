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

const allowedOrigins = ["http://localhost:5174"];

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: allowedOrigins, credentials: true }));

// Sample route to check server status
app.get("/", (req, res) => {
  res.send("OAuth-JWT Backend is running");
});

// Api routes
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
