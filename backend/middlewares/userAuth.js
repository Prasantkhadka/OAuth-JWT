import jwt from "jsonwebtoken";

const userAuth = (req, res, next) => {
  // cookie-parser places cookies on req.cookies
  const token = req.cookies && req.cookies.token;
  if (!token) {
    return res
      .status(401)
      .json({ message: "Not authorized, please login again" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded && decoded.id) {
      req.user = { id: decoded.id };
      return next();
    }
    return res
      .status(401)
      .json({ message: "Not authorized, please login again" });
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

export default userAuth;
