import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_jwt_secret"; // Use a strong, secure key in production

app.use(bodyParser.json());
app.use(cors());

// Simulación de base de datos (array en memoria)
const users = [];

// Middleware: Verify Token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// ✅ Nueva ruta: registrar usuario
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  // Validar si el usuario ya existe
  const existingUser = users.find((u) => u.email === email);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Encriptar contraseña
  const hashedPassword = await bcrypt.hash(password, 10);

  // Guardar usuario en "base de datos"
  const user = { id: users.length + 1, email, password: hashedPassword };
  users.push(user);

  res.status(201).json({ message: "User registered successfully!" });
});

// Login (ya lo tenías)
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
  res.status(200).json({ token });
});

// Ruta protegida (ya la tenías)
app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ message: "Protected data accessed", user: req.user });
});

// Servidor
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);
