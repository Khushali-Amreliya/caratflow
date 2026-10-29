
const jwt = require("jsonwebtoken");

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authentication token is required.",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "caratflow-api",
      audience: "caratflow-erp",
    });

    req.firmId = decoded.sub;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired authentication token.",
    });
  }
}

module.exports = authMiddleware;
