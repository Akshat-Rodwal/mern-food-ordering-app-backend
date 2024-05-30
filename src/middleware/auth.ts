import { NextFunction, Request, Response } from "express";
import { auth } from "express-oauth2-jwt-bearer";
import jwt from "jsonwebtoken";
import User from "../models/user";

// Extend Express Request interface to include userId and auth0Id
declare global {
  namespace Express {
    interface Request {
      userId: string;
      auth0Id: string;
    }
  }
}

// Middleware to check JWT
export const jwtCheck = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: 'RS256',
});

// Middleware to parse JWT and set userId and auth0Id in the request object
export const jwtParse = async (req: Request, res: Response, next: NextFunction) => {
  const { authorization } = req.headers;

  // Check if the authorization header is present and starts with 'Bearer'
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.sendStatus(401); // Unauthorized
  }

  const token = authorization.split(" ")[1];

  try {
    // Decode the token to get the payload
    const decoded = jwt.decode(token) as jwt.JwtPayload;
    const auth0Id = decoded.sub;

    // Find the user by auth0Id in the database
    const user = await User.findOne({ auth0Id });

    // Check if the user exists and has a valid _id
    if (!user || !user._id) {
      return res.sendStatus(401); // Unauthorized
    }

    // Set the auth0Id and userId in the request object
    req.auth0Id = auth0Id as string;
    req.userId = user._id.toString();

    // Proceed to the next middleware
    next();
  } catch (error) {
    // Handle any errors and respond with 401 Unauthorized
    console.error("Error parsing JWT:", error);
    return res.sendStatus(401); // Unauthorized
  }
};
