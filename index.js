const express = require("express");
const fs = require("fs");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const QRCode = require("qrcode");

const app = express();
app.use(cors());
app.use(express.json());

const DB = {
  products: "./database/products.json",
  orders: "./database/orders.json",
  admins: "./database/admins.json"
};

function read(file) {
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file));
}

function write(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const SECRET = "LBS_SHOP_SECRET";

// 🔐 Middleware auth admin
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  try {
    req.admin = jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// 🔐 Création admin (une seule fois)
app.post("/api/admin/create", async (req, res) => {
  const admins = read(DB.admins);
  const hash = await bcrypt.hash(req.body.password, 10);

  admins.push({
    id: crypto.randomUUID(),
    username: req.body.username,
    password: hash
  });

  write(DB.admins, admins);
  res.json({ success: true });
});

// 🔐 Login admin
app.post("/api/admin/login", async (req, res) => {
  const admins = read(DB.admins);
  const admin = admins.find(a => a.username === req.body.username);

  if (!admin) return res.sendStatus(401);

  const ok = await bcrypt.compare(req.body.password, admin.password);
  if (!ok) return res.sendStatus(401);

  const token = jwt.sign({ id: admin.id }, SECRET, { expiresIn: "2d" });
  res.json({ token });
});

// 🛍 Produits
app.get("/api/products", (req, res) => {
  res.json(read(DB.products));
});

app.post("/api/admin/product", auth, (req, res) => {
  const products = read(DB.products);

  products.push({
    id: crypto.randomUUID(),
    ...req.body,
    createdAt: new Date()
  });

  write(DB.products, products);
  res.json({ success: true });
});

app.delete("/api/admin/product/:id", auth, (req, res) => {
  let products = read(DB.products);
  products = products.filter(p => p.id !== req.params.id);
  write(DB.products, products);
  res.json({ success: true });
});

// 🛒 Commande client
app.post("/api/order", (req, res) => {
  const orders = read(DB.orders);

  orders.push({
    id: crypto.randomUUID(),
    ...req.body,
    status: "EN_ATTENTE",
    createdAt: new Date()
  });

  write(DB.orders, orders);
  res.json({ success: true });
});

// 📦 Commandes admin
app.get("/api/admin/orders", auth, (req, res) => {
  res.json(read(DB.orders));
});

// 💳 Validation paiement + QR
app.post("/api/admin/confirm/:id", auth, async (req, res) => {
  const orders = read(DB.orders);
  const order = orders.find(o => o.id === req.params.id);

  if (!order) return res.sendStatus(404);

  const token = crypto.randomBytes(32).toString("hex");

  order.status = "PAYE";
  order.token = token;

  const qr = await QRCode.toDataURL(JSON.stringify({
    id: order.id,
    token
  }));

  order.qr = qr;
  write(DB.orders, orders);

  res.json({ success: true, order });
});

// 🚚 Scan livreur
app.post("/api/scan", (req, res) => {
  const { id, token } = req.body;
  const orders = read(DB.orders);

  const order = orders.find(o => o.id === id && o.token === token);

  if (!order || order.delivered) return res.json({ valid: false });

  order.delivered = true;
  write(DB.orders, orders);

  res.json({ valid: true });
});

app.listen(3000, () => console.log("🔥 LBS SHOP PRO API lancé"));
