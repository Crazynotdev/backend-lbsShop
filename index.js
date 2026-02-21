const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs").promises;
const fsSync = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const morgan = require("morgan");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SECRET";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

if (!process.env.JWT_SECRET) {
  console.warn("⚠ ATTENTION: JWT_SECRET non défini, sécurité faible !");
}

// ========================
// DOSSIERS AUTO
// ========================

["db", "uploads", "logs"].forEach(dir => {
  if (!fsSync.existsSync(dir)) fsSync.mkdirSync(dir, { recursive: true });
});

// ========================
// DB
// ========================

const DB = {
  products: "./db/products.json",
  orders: "./db/orders.json",
  users: "./db/users.json",
  settings: "./db/settings.json"
};

async function initDB() {
  for (const file of Object.values(DB)) {
    try {
      await fs.access(file);
    } catch {
      await fs.writeFile(file, "[]");
    }
  }

  const users = JSON.parse(await fs.readFile(DB.users));
  if (users.length === 0) {
    users.push({
      id: uuidv4(),
      username: ADMIN_USERNAME,
      password: await bcrypt.hash(ADMIN_PASSWORD, 10),
      role: "admin",
      createdAt: new Date().toISOString()
    });
    await fs.writeFile(DB.users, JSON.stringify(users, null, 2));
    console.log("✅ Admin créé par défaut");
  }
}
initDB();

// ========================
// MIDDLEWARES
// ========================

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));

app.use(morgan("combined", {
  stream: { write: msg => fsSync.appendFileSync("./logs/access.log", msg) }
}));

app.use(cors({
  origin: "*",
  credentials: true
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
}));

// ========================
// UTILS
// ========================

async function read(file) {
  return JSON.parse(await fs.readFile(file, "utf8"));
}

async function write(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// ========================
// AUTH
// ========================

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token manquant" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalide" });
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Accès refusé" });
  next();
}

// ========================
// LOGIN
// ========================

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const users = await read(DB.users);
  const user = users.find(u => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Identifiants incorrects" });
  }

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "24h" });

  res.json({ success: true, token, user: { id: user.id, role: user.role } });
});

// ========================
// UPLOAD
// ========================

const storage = multer.diskStorage({
  destination: "uploads",
  filename: (req, file, cb) => cb(null, Date.now() + "-" + uuidv4() + path.extname(file.originalname))
});

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }});

// ========================
// PRODUITS CRUD
// ========================

app.get("/api/products", async (req, res) => {
  res.json({ success: true, products: await read(DB.products) });
});

app.post("/api/admin/products", authenticateToken, isAdmin, upload.single("image"), async (req, res) => {
  const products = await read(DB.products);

  const product = {
    id: uuidv4(),
    ...req.body,
    price: Number(req.body.price),
    promo: Number(req.body.promo || 0),
    finalPrice: req.body.promo ? Number(req.body.price) * (1 - Number(req.body.promo) / 100) : Number(req.body.price),
    image: req.file ? `/uploads/${req.file.filename}` : null,
    createdAt: new Date().toISOString()
  };

  products.push(product);
  await write(DB.products, products);

  res.json({ success: true, product });
});

// ========================
// SERVEUR
// ========================

app.listen(PORT, () => {
  console.log(`🔥 API READY → http://localhost:${PORT}`);
});
