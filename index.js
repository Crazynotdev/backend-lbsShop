const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs").promises;
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
const JWT_SECRET = process.env.JWT_SECRET || "lbs-shop-super-secret-key-2024";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// ========================
// CONFIGURATION & SÉCURITÉ
// ========================

// Dossiers nécessaires
const dirs = ["./db", "./uploads", "./logs"];
dirs.forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Base de données
const DB = {
  products: "./db/products.json",
  orders: "./db/orders.json",
  users: "./db/users.json",
  settings: "./db/settings.json"
};

// Initialiser les fichiers DB
async function initDB() {
  for (const [key, file] of Object.entries(DB)) {
    try {
      await fs.access(file);
    } catch {
      await fs.writeFile(file, JSON.stringify([]));
    }
  }
  
  // Créer admin par défaut
  const users = await read(DB.users);
  if (users.length === 0) {
    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
    users.push({
      id: uuidv4(),
      username: ADMIN_USERNAME,
      password: hashedPassword,
      role: "admin",
      createdAt: new Date().toISOString()
    });
    await write(DB.users, users);
  }
}
initDB();

// Middleware sécurité
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(compression());
app.use(morgan("combined", {
  stream: { write: message => fs.appendFile("./logs/access.log", message) }
}));

// CORS configuré
app.use(cors({
  origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limite 100 requêtes par IP
  message: { error: "Trop de requêtes, réessayez plus tard" }
});
app.use("/api/", limiter);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));

// ========================
// UTILS
// ========================

async function read(file) {
  try {
    const data = await fs.readFile(file, "utf8");
    return JSON.parse(data);
  } catch {
    return [];
  }
}

async function write(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// Logger
const logger = {
  info: (msg) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`),
  error: (msg) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`),
  warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`)
};

// ========================
// AUTHENTIFICATION
// ========================

// Middleware vérification token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ error: "Non authentifié" });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token invalide" });
    }
    req.user = user;
    next();
  });
}

// Middleware vérification admin
function isAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Accès interdit" });
  }
  next();
}

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: "Identifiants requis" });
    }
    
    const users = await read(DB.users);
    const user = users.find(u => u.username === username);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      logger.warn(`Tentative de connexion échouée: ${username}`);
      return res.status(401).json({ error: "Identifiants incorrects" });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );
    
    logger.info(`Connexion réussie: ${username}`);
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    logger.error(`Erreur login: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ========================
// CONFIG MULTER (Upload)
// ========================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = "uploads/";
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ["image/jpeg", "image/png", "image/webp", "image/jpg"];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Format de fichier non supporté"), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB max
});

// ========================
// ROUTES PRODUITS
// ========================

// GET /api/products - Liste produits (public)
app.get("/api/products", async (req, res) => {
  try {
    const { category, minPrice, maxPrice, search, sort } = req.query;
    let products = await read(DB.products);
    
    // Filtres
    if (category && category !== "all") {
      products = products.filter(p => p.category === category);
    }
    
    if (minPrice) {
      products = products.filter(p => p.finalPrice >= Number(minPrice));
    }
    
    if (maxPrice) {
      products = products.filter(p => p.finalPrice <= Number(maxPrice));
    }
    
    if (search) {
      const searchLower = search.toLowerCase();
      products = products.filter(p => 
        p.name.toLowerCase().includes(searchLower) ||
        p.description?.toLowerCase().includes(searchLower)
      );
    }
    
    // Tri
    if (sort) {
      switch(sort) {
        case "price_asc":
          products.sort((a, b) => a.finalPrice - b.finalPrice);
          break;
        case "price_desc":
          products.sort((a, b) => b.finalPrice - a.finalPrice);
          break;
        case "newest":
          products.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
          break;
        case "name":
          products.sort((a, b) => a.name.localeCompare(b.name));
          break;
      }
    }
    
    res.json({
      success: true,
      count: products.length,
      products
    });
  } catch (error) {
    logger.error(`Erreur GET products: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// GET /api/products/:id - Détail produit
app.get("/api/products/:id", async (req, res) => {
  try {
    const products = await read(DB.products);
    const product = products.find(p => p.id === req.params.id);
    
    if (!product) {
      return res.status(404).json({ error: "Produit non trouvé" });
    }
    
    res.json({ success: true, product });
  } catch (error) {
    logger.error(`Erreur GET product: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// POST /api/admin/products - Ajouter produit (admin)
app.post("/api/admin/products", authenticateToken, isAdmin, upload.single("image"), async (req, res) => {
  try {
    const { name, price, promo, category, description, stock } = req.body;
    
    // Validation
    if (!name || !price || !category) {
      return res.status(400).json({ error: "Champs requis manquants" });
    }
    
    if (isNaN(price) || price <= 0) {
      return res.status(400).json({ error: "Prix invalide" });
    }
    
    const products = await read(DB.products);
    
    const product = {
      id: uuidv4(),
      name: name.trim(),
      price: Number(price),
      promo: promo ? Number(promo) : 0,
      finalPrice: promo ? Number(price) * (1 - Number(promo) / 100) : Number(price),
      category: category.trim(),
      description: description || "",
      stock: stock ? Number(stock) : 0,
      image: req.file ? `/uploads/${req.file.filename}` : null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      isNew: true
    };
    
    products.push(product);
    await write(DB.products, products);
    
    logger.info(`Produit ajouté: ${product.name} (${product.id})`);
    res.json({ success: true, product });
  } catch (error) {
    logger.error(`Erreur POST product: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// PUT /api/admin/products/:id - Modifier produit
app.put("/api/admin/products/:id", authenticateToken, isAdmin, upload.single("image"), async (req, res) => {
  try {
    const products = await read(DB.products);
    const index = products.findIndex(p => p.id === req.params.id);
    
    if (index === -1) {
      return res.status(404).json({ error: "Produit non trouvé" });
    }
    
    const { name, price, promo, category, description, stock } = req.body;
    
    // Mise à jour
    products[index] = {
      ...products[index],
      name: name?.trim() || products[index].name,
      price: price ? Number(price) : products[index].price,
      promo: promo !== undefined ? Number(promo) : products[index].promo,
      finalPrice: promo ? Number(price || products[index].price) * (1 - Number(promo) / 100) : 
                 (price ? Number(price) : products[index].price),
      category: category?.trim() || products[index].category,
      description: description !== undefined ? description : products[index].description,
      stock: stock !== undefined ? Number(stock) : products[index].stock,
      image: req.file ? `/uploads/${req.file.filename}` : products[index].image,
      updatedAt: new Date().toISOString(),
      isNew: false
    };
    
    await write(DB.products, products);
    
    logger.info(`Produit modifié: ${products[index].name}`);
    res.json({ success: true, product: products[index] });
  } catch (error) {
    logger.error(`Erreur PUT product: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// DELETE /api/admin/products/:id - Supprimer produit
app.delete("/api/admin/products/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    let products = await read(DB.products);
    const productToDelete = products.find(p => p.id === req.params.id);
    
    if (!productToDelete) {
      return res.status(404).json({ error: "Produit non trouvé" });
    }
    
    // Supprimer l'image associée
    if (productToDelete.image) {
      const imagePath = path.join(__dirname, productToDelete.image);
      try {
        await fs.unlink(imagePath);
      } catch (e) {
        logger.warn(`Image non trouvée: ${imagePath}`);
      }
    }
    
    products = products.filter(p => p.id !== req.params.id);
    await write(DB.products, products);
    
    logger.info(`Produit supprimé: ${productToDelete.name}`);
    res.json({ success: true, message: "Produit supprimé" });
  } catch (error) {
    logger.error(`Erreur DELETE product: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ========================
// ROUTES COMMANDES
// ========================

// POST /api/orders - Nouvelle commande (public)
app.post("/api/orders", async (req, res) => {
  try {
    const { name, phone, location, items } = req.body;
    
    // Validation
    if (!name?.trim() || !phone?.trim() || !location?.trim()) {
      return res.status(400).json({ error: "Tous les champs sont requis" });
    }
    
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Panier vide" });
    }
    
    // Validation téléphone (format gabonais)
    const phoneRegex = /^(0|00241)?[6-7][0-9]{7}$/;
    if (!phoneRegex.test(phone.replace(/\s/g, ""))) {
      return res.status(400).json({ error: "Format téléphone invalide" });
    }
    
    const orders = await read(DB.orders);
    
    const total = items.reduce((sum, item) => sum + (item.finalPrice || item.price || 0), 0);
    
    const order = {
      id: `CMD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      name: name.trim(),
      phone: phone.trim(),
      location: location.trim(),
      items: items.map(item => ({
        id: item.id,
        name: item.name,
        price: item.finalPrice || item.price,
        quantity: item.quantity || 1
      })),
      total,
      status: "en attente",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    orders.push(order);
    await write(DB.orders, orders);
    
    logger.info(`Nouvelle commande: ${order.id} - ${order.name}`);
    res.json({
      success: true,
      message: "Commande enregistrée",
      orderId: order.id
    });
  } catch (error) {
    logger.error(`Erreur POST order: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// GET /api/admin/orders - Liste commandes (admin)
app.get("/api/admin/orders", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, startDate, endDate } = req.query;
    let orders = await read(DB.orders);
    
    // Filtres
    if (status) {
      orders = orders.filter(o => o.status === status);
    }
    
    if (startDate) {
      orders = orders.filter(o => new Date(o.createdAt) >= new Date(startDate));
    }
    
    if (endDate) {
      orders = orders.filter(o => new Date(o.createdAt) <= new Date(endDate));
    }
    
    // Tri par date décroissante
    orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    res.json({
      success: true,
      count: orders.length,
      orders
    });
  } catch (error) {
    logger.error(`Erreur GET orders: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// PUT /api/admin/orders/:id - Mettre à jour statut commande
app.put("/api/admin/orders/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const validStatus = ["en attente", "confirmée", "préparée", "livrée", "annulée"];
    
    if (!status || !validStatus.includes(status)) {
      return res.status(400).json({ error: "Statut invalide" });
    }
    
    const orders = await read(DB.orders);
    const index = orders.findIndex(o => o.id === req.params.id);
    
    if (index === -1) {
      return res.status(404).json({ error: "Commande non trouvée" });
    }
    
    orders[index].status = status;
    orders[index].updatedAt = new Date().toISOString();
    await write(DB.orders, orders);
    
    logger.info(`Commande ${req.params.id} mise à jour: ${status}`);
    res.json({ success: true, order: orders[index] });
  } catch (error) {
    logger.error(`Erreur PUT order: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// DELETE /api/admin/orders/:id - Supprimer commande
app.delete("/api/admin/orders/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    let orders = await read(DB.orders);
    const orderExists = orders.some(o => o.id === req.params.id);
    
    if (!orderExists) {
      return res.status(404).json({ error: "Commande non trouvée" });
    }
    
    orders = orders.filter(o => o.id !== req.params.id);
    await write(DB.orders, orders);
    
    logger.info(`Commande supprimée: ${req.params.id}`);
    res.json({ success: true, message: "Commande supprimée" });
  } catch (error) {
    logger.error(`Erreur DELETE order: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ========================
// STATISTIQUES
// ========================

// GET /api/admin/stats - Dashboard stats
app.get("/api/admin/stats", authenticateToken, isAdmin, async (req, res) => {
  try {
    const products = await read(DB.products);
    const orders = await read(DB.orders);
    
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    
    // Statistiques produits
    const totalProducts = products.length;
    const outOfStock = products.filter(p => p.stock === 0).length;
    const avgPrice = products.reduce((sum, p) => sum + p.finalPrice, 0) / totalProducts || 0;
    
    // Statistiques commandes
    const totalOrders = orders.length;
    const todayOrders = orders.filter(o => new Date(o.createdAt) >= today).length;
    const pendingOrders = orders.filter(o => o.status === "en attente").length;
    const totalRevenue = orders.reduce((sum, o) => sum + o.total, 0);
    
    // Commandes par mois (pour graphique)
    const last6Months = [];
    for (let i = 5; i >= 0; i--) {
      const month = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthOrders = orders.filter(o => {
        const orderDate = new Date(o.createdAt);
        return orderDate.getMonth() === month.getMonth() &&
               orderDate.getFullYear() === month.getFullYear();
      });
      last6Months.push({
        month: month.toLocaleString("fr-FR", { month: "short" }),
        count: monthOrders.length,
        revenue: monthOrders.reduce((sum, o) => sum + o.total, 0)
      });
    }
    
    res.json({
      success: true,
      stats: {
        products: { total: totalProducts, outOfStock, avgPrice: Math.round(avgPrice) },
        orders: { total: totalOrders, today: todayOrders, pending: pendingOrders, totalRevenue },
        timeline: last6Months
      }
    });
  } catch (error) {
    logger.error(`Erreur GET stats: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ========================
// UPLOADS (Gestion fichiers)
// ========================

// GET /api/uploads - Liste fichiers (admin)
app.get("/api/uploads", authenticateToken, isAdmin, async (req, res) => {
  try {
    const files = await fs.readdir("uploads/");
    const filesInfo = await Promise.all(
      files.map(async (file) => {
        const stat = await fs.stat(path.join("uploads/", file));
        return {
          name: file,
          size: stat.size,
          createdAt: stat.birthtime,
          url: `/uploads/${file}`
        };
      })
    );
    res.json({ success: true, files: filesInfo });
  } catch (error) {
    logger.error(`Erreur GET uploads: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ========================
// HEALTH CHECK & ROOT
// ========================

app.get("/", (req, res) => {
  res.json({
    name: "LBS SHOP API",
    version: "2.0.0",
    status: "online",
    endpoints: {
      public: ["/api/products", "/api/orders"],
      admin: ["/api/admin/products", "/api/admin/orders", "/api/admin/stats"]
    },
    timestamp: new Date().toISOString()
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ========================
// GESTION DES ERREURS
// ========================

// 404
app.use((req, res) => {
  res.status(404).json({ error: "Route non trouvée" });
});

// Error handler global
app.use((err, req, res, next) => {
  logger.error(`Erreur globale: ${err.message}`);
  
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "Fichier trop volumineux (max 5MB)" });
    }
    return res.status(400).json({ error: err.message });
  }
  
  res.status(500).json({
    error: process.env.NODE_ENV === "production" 
      ? "Erreur interne du serveur" 
      : err.message
  });
});

// ========================
// DÉMARRAGE
// ========================

app.listen(PORT, () => {
  logger.info(`🔥 LBS SHOP API v2.0.0`);
  logger.info(`📍 http://localhost:${PORT}`);
  logger.info(`📊 Mode: ${process.env.NODE_ENV || "development"}`);
});
