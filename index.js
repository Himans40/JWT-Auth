require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { PrismaClient } = require("./generated/prisma");
const { PrismaPg } = require("@prisma/adapter-pg");

const app = express();
const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWTSECRET;
const SALT_ROUNDS = 10;
const JWT_EXPIRES_IN = "1h";

app.use(express.json());

function generateJti() {
  return crypto.randomBytes(16).toString("hex");
}

function generateToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    jti: generateJti(),
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: missing or invalid token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: invalid or expired token" });
  }
}

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password || typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid input: email and password are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Invalid input: password must be at least 6 characters" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (existingUser) {
      return res.status(409).json({ error: "Conflict: email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
      },
    });

    const token = generateToken(user);

    return res.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: "Invalid input" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password || typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Missing or invalid input" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    const passwordValid = user ? await bcrypt.compare(password, user.password) : false;

    if (!user || !passwordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = generateToken(user);

    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      token,
    });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: "Missing or invalid input" });
  }
});

app.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found: user does not exist" });
    }

    return res.status(200).json(user);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        email: true,
        name: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "Not Found: user does not exist" });
    }

    const displayName = user.name || user.email;
    return res.status(200).json({ message: `Welcome, ${displayName}` });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
