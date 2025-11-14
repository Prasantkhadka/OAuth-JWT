import jwt from "jsonwebtoken";

/*
  userAuth middleware

  - Purpose: Protect routes by ensuring a valid access token is present.
  - Behavior:
    * Reads the access token from the `token` HttpOnly cookie (cookie-parser
      must be enabled on the app).
    * Verifies the JWT signature and extracts the user id.
    * On success, attaches `req.user = { id }` and calls `next()`.
    * On failure, returns 401 so the frontend can redirect to login.
*/
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
