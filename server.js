const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();
const bcrypt = require('bcryptjs');  // Ajoutez cette ligne
const { LICENCE_SETTINGS } = require('./config');
const {
  generateLicence,
  validateLicence,
  revokeLicence,
  markLicenceUsed,
  initLicenceFile,
  getLicenceLogs,
  loadLicenceData
} = require('./licence');

const {
  loadData,
  saveData,
  initDataStructure,
  logAction,
  generateId,
  addStockItem,
  updateStockItem,
  deleteStockItem,
  checkStockAlerts,
  addCommande,
  validerCommande,
  annulerCommande,
  addRecette,
  addRecetteWithStockUpdate,
  deleteRecette,
  addVente,
  updateStockForOrder,
  validerVente,
  addStaffMember,
  getUserById,
  removeStaffMember,
  getStaffMembers,
  hashPassword,
  verifyPassword,
  createUser,
  findUserByEmail,
  generateAuthToken,
  validateLicenceKey,
  registerLicence,
  updateUserLicence
} = require('./jsonManager');

const app = express();
const SECRET_KEY = process.env.SECRET_KEY;
const MASTER_API_KEY = process.env.MASTER_API_KEY;
const uploadDir = path.join(__dirname, 'uploads');

// Middleware configuration
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'x-licence-key']
}));
app.use(express.json());

// File system configuration for uploads
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-z0-9.]/gi, '_');
    cb(null, `${Date.now()}-${safeName}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Seules les images (JPEG/PNG/WEBP) sont autorisées'));
    }
  }
});

// Middleware for handling file permissions
app.use((req, res, next) => {
  if (req.file) {
    fs.chmod(req.file.path, 0o644, (err) => {
      if (err) console.error('Erreur permissions:', err);
    });
  }
  next();
});

// Static file server configuration
app.use('/uploads', express.static(uploadDir, {
  setHeaders: (res) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
  }
}));

// Middleware d'authentification standard
function authenticate(req, res, next) {
  const authHeader = req.header('Authorization');
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      error: 'Token manquant',
      code: 'MISSING_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    req.licence = { key: decoded.licenceKey }; // <-- ici on ajoute la licence
    next();
  } catch (err) {
    res.status(401).json({
      error: 'Token invalide ou expiré',
      code: 'INVALID_TOKEN'
    });
  }
}
// Authentication middleware
async function licenceCheckMiddleware(req, res, next) {
  try {
    const licenceKey = req.headers['x-licence-key'];

    if (!licenceKey) {
      return res.status(400).json({
        error: 'LicenceKey manquante dans les headers',
        code: 'MISSING_LICENCE_KEY'
      });
    }

    const licenceData = await loadData('licences');

    // Recherche la licence correspondant à la clé
    const licence = Array.isArray(licenceData)
      ? licenceData.find(l => l.key === licenceKey)
      : licenceData.licences?.find(l => l.key === licenceKey);

    if (!licence) {
      return res.status(403).json({
        error: 'Licence inconnue',
        code: 'UNKNOWN_LICENCE'
      });
    }

    if (licence.revoked || licenceData.revokedKeys?.includes(licenceKey)) {
      return res.status(403).json({
        error: 'Licence révoquée',
        code: 'REVOKED_LICENCE'
      });
    }

    // Attache la licence valide à la requête
    req.licence = { key: licenceKey, data: licence };

    next();
  } catch (error) {
    console.error('Erreur licenceCheckMiddleware:', error);
    res.status(500).json({
      error: 'Erreur de vérification de licence',
      code: 'LICENCE_CHECK_ERROR'
    });
  }
}
// Nouveau middleware masterLicenceRequired
function masterLicenceRequired(req, res, next) {
  const licenceKey = req.headers['x-licence-key'] ||
                   req.headers['x-master-key'] ||
                   (req.headers['authorization']?.startsWith('Bearer ') &&
                    req.headers['authorization'].split(' ')[1]) ||
                   req.body?.key;

  console.log('=== MASTER AUTH DEBUG ===\nClé reçue:', licenceKey);

  if (licenceKey === process.env.MASTER_API_KEY) {
    console.log('Accès master via clé globale');
    return next();
  }

  try {
    if (!licenceKey) {
      throw new Error('Aucune clé de licence fournie');
    }

    const validation = validateLicence(licenceKey);

    console.log('Résultat validation:', {
      valid: validation.valid,
      isMaster: validation.isMaster,
      key: licenceKey.substring(0, 6) + '...'
    });

    if (!validation.valid) {
      throw new Error('Licence invalide ou expirée');
    }

    if (!validation.isMaster) {
      throw new Error('Une licence master est requise');
    }

    req.licence = validation.licence;
    next();

  } catch (error) {
    console.error('Erreur masterLicenceRequired:', {
      error: error.message,
      providedKey: licenceKey?.substring(0, 6) + '...',
      route: req.path
    });

    res.status(403).json({
      error: 'Accès non autorisé',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      code: 'MASTER_ACCESS_DENIED'
    });
  }
}

// Licence check middleware


// ===================== ROUTES LICENCE =====================
app.post('/api/licence/validate', (req, res) => {
  try {
    const { key } = req.body;
    console.log(`=== DEBUG VALIDATION START ===\nClé reçue: ${key}`);

    if (key === MASTER_API_KEY) {
      const response = {
        valid: true,
        isMaster: true,
        isExpired: false,
        expiresAt: null,
        clientInfo: {
          name: "MASTER_LICENCE_ADMIN",
          email: "admin@restaurant.com",
          isMaster: true
        },
        isActive: true
      };
      console.log('Validation licence (MASTER):', { ...response, key: key.substring(0, 3) + '...' });
      return res.json(response);
    }

    const validation = validateLicence(key);
    const response = {
      valid: validation.valid,
      isMaster: validation.isMaster,
      isExpired: validation.isExpired || false,
      expiresAt: validation.expiresAt,
      clientInfo: validation.licence?.clientInfo || null,
      isActive: validation.licence?.isActive !== false,
      ...(!validation.valid && { reason: validation.reason })
    };

    console.log('Validation licence:', {
      ...response,
      key: key.substring(0, 3) + '...' + key.substring(key.length - 3),
      timestamp: new Date().toISOString()
    });

    res.json(response);
  } catch (error) {
    console.error('Erreur validation:', error);
    res.status(400).json({
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

app.post('/api/master/licences/generate', masterLicenceRequired, (req, res) => {
  try {
    const { clientInfo = {}, durationType = '1y' } = req.body;

    if (!clientInfo.name || !clientInfo.email) {
      return res.status(400).json({
        error: 'Informations client incomplètes',
        required: ['clientInfo.name', 'clientInfo.email']
      });
    }

    const newLicence = generateLicence(clientInfo, 'system');

    res.status(201).json({
      licence: {
        key: newLicence.key,
        clientInfo: newLicence.clientInfo,
        expiresAt: newLicence.expiresAt
      },
      _meta: {
        generatedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(400).json({
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

app.post('/api/master/licences/revoke', masterLicenceRequired, (req, res) => {
  try {
    const { key, reason } = req.body;

    if (!key) {
      return res.status(400).json({
        error: 'Clé de licence requise',
        requiredFields: ['key']
      });
    }

    const result = revokeLicence(key, reason || 'admin_revocation');

    res.json({
      success: result.success,
      message: result.message || `Licence ${key} révoquée`,
      key,
      revokedAt: new Date().toISOString(),
      reason: reason || 'admin_revocation'
    });
  } catch (error) {
    res.status(500).json({
      error: `Erreur de révocation: ${error.message}`,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

app.post('/api/master/licences/mark-used', masterLicenceRequired, (req, res) => {
  try {
    const { key, userId } = req.body;

    if (!key || !userId) {
      return res.status(400).json({
        error: 'Clé de licence et ID utilisateur requis',
        requiredFields: ['key', 'userId']
      });
    }

    const result = markLicenceUsed(key, userId);

    res.json({
      success: result.success,
      message: result.message || `Licence ${key} marquée comme utilisée`,
      key,
      userId,
      markedAt: new Date().toISOString()
    });
  } catch (error) {
    res.status(400).json({
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

app.get('/api/master/licences', masterLicenceRequired, (req, res) => {
  try {
    const { status } = req.query;
    const licenceData = loadLicenceData();

    let formattedLicences = licenceData.licences.map(licence => ({
      key: licence.key,
      clientInfo: licence.clientInfo || {},
      createdAt: licence.createdAt,
      expiresAt: licence.expiresAt,
      durationType: licence.durationType || '1y',
      isActive: licence.isActive !== false,
      revoked: !!licence.revoked,
      revokedAt: licence.revokedAt,
      revokedReason: licence.revokedReason,
      usedBy: licence.usedBy || null,
    }));

    if (status === 'active') {
      formattedLicences = formattedLicences.filter(l =>
        !l.revoked &&
        l.isActive &&
        !l.isExpired
      );
    } else if (status === 'revoked') {
      formattedLicences = formattedLicences.filter(l => l.revoked);
    } else if (status === 'expired') {
      formattedLicences = formattedLicences.filter(l => l.isExpired);
    }

    const validCount = formattedLicences.filter(l =>
      !l.revoked &&
      l.isActive &&
      !l.isExpired
    ).length;

    res.json({
      licences: formattedLicences,
      count: formattedLicences.length,
      validCount,
      revokedCount: formattedLicences.filter(l => l.revoked).length,
      expiredCount: formattedLicences.filter(l => l.isExpired).length,
    });

  } catch (error) {
    console.error('Erreur licence:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({
      error: 'Erreur de chargement des licences',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ===================== ROUTES UTILISATEUR =====================
app.post('/api/setup', async (req, res) => {
  try {
    // Vérification de la licence
    const licenceKey = req.headers['x-licence-key'];
    if (!licenceKey || licenceKey !== 'LIC-1-B21585D3') {
      return res.status(403).json({ error: 'Licence key invalide' });
    }

    // Charge les utilisateurs (avec le bon fileKey)
    const users = await loadData('users'); // <-- ICI le changement clé

    if (users.length > 0) {
      return res.status(400).json({ error: 'Le système a déjà été initialisé' });
    }

    const { email, password, secretQuestion, secretAnswer } = req.body;
    if (!email || !password || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }

    const hashedPassword = await hashPassword(password);

    const superAdmin = {
      id: generateId(users),
      email,
      passwordHash: hashedPassword,
      role: 'superAdmin',
      secretQuestion,
      secretAnswer,
      createdAt: new Date().toISOString(),
      licenceKey
    };

    // Sauvegarde le nouvel utilisateur
    const updatedUsers = [...users, superAdmin];
    await saveData('users', updatedUsers); // <-- ICI aussi

    const token = jwt.sign(
      { userId: superAdmin.id, email, role: 'superAdmin', licenceKey },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true,
      token,
      user: {
        id: superAdmin.id,
        email: superAdmin.email,
        role: superAdmin.role
      }
    });

  } catch (error) {
    console.error('Setup error:', error);
    res.status(500).json({ 
      error: 'Erreur lors de l\'initialisation',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.post('/api/login', licenceCheckMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email et mot de passe requis',
        code: 'MISSING_CREDENTIALS'
      });
    }

    const users = await loadData('users');
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const isPasswordValid = bcrypt.compareSync(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    // Log pour debug
    console.log('[LOGIN] Licence attachée :', req.licence?.key);

    if (!req.licence?.key) {
      return res.status(403).json({
        error: 'Licence non fournie',
        code: 'MISSING_LICENCE'
      });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        licenceKey: req.licence.key
      },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('[LOGIN ERROR]:', error.message);
    res.status(500).json({ error: 'Erreur serveur', code: 'SERVER_ERROR' });
  }
});


app.post('/api/reset-password', licenceCheckMiddleware, async (req, res) => {
  try {
    const { email, newPassword, secretAnswer } = req.body;
    
    // Charge les données SYNCHRONES (comme avant)
    const data = loadData();
    
    // Trouve l'utilisateur
    const user = data.data.users.find(u => u.email === email);
    if (!user || user.secretAnswer !== secretAnswer) {
      return res.status(400).json({ 
        error: 'Informations de réinitialisation invalides' 
      });
    }

    // Met à jour le mot de passe
    user.passwordHash = await hashPassword(newPassword); // hashPassword reste async
    
    // Sauvegarde SYNCHRONE
    saveData(data);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      error: error.message,
      code: 'PASSWORD_RESET_FAILED' 
    });
  }
});

// ===================== ROUTES SÉCURISÉES =====================
app.post('/api/dashboard/licences/generate', authenticate, (req, res) => {
  try {
    const { clientInfo = {}, durationType = '1y' } = req.body;

    if (!clientInfo.name || !clientInfo.email) {
      return res.status(400).json({
        error: 'Informations client incomplètes',
        required: ['clientInfo.name', 'clientInfo.email']
      });
    }

    const newLicence = generateLicence(clientInfo, req.user.userId);

    res.status(201).json({
      licence: {
        key: newLicence.key,
        clientInfo: newLicence.clientInfo,
        expiresAt: newLicence.expiresAt
      },
      _meta: {
        generatedAt: new Date().toISOString(),
        generatedBy: req.user.userId
      }
    });
  } catch (error) {
    res.status(400).json({
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ===================== STOCK ROUTES =====================
// GET /api/stock - Récupère le stock filtré par licence
app.get('/api/stock', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const data = loadData('main'); // Assurez-vous que 'main' est le bon fileKey
    const filteredStock = data.data.stock.filter(item => item.licenceKey === licenceKey);
    res.json(filteredStock);
  } catch (error) {
    console.error('GET /api/stock error:', error);
    res.status(500).json({
      error: 'Failed to load stock',
      details: error.message
    });
  }
});


// POST /api/stock - Ajoute un nouvel élément
app.post('/api/stock', authenticate, (req, res) => {
  try {
    // Validation
    if (!req.body.nom || req.body.quantite === undefined) {
      return res.status(400).json({ error: 'Name and quantity are required' });
    }

    const newItem = addStockItem({
      nom: req.body.nom,
      quantite: parseInt(req.body.quantite) || 0,
      prixAchat: parseFloat(req.body.prixAchat) || 0,
      seuilAlerte: parseInt(req.body.seuilAlerte) || 5,
      categorie: req.body.categorie || 'autre',
      user: req.user.userId,
      licenceKey: req.licence.key
    }, req.licence.key);

    res.status(201).json(newItem);
  } catch (error) {
    console.error('POST /api/stock error:', error);
    res.status(500).json({
      error: 'Failed to add item',
      details: error.message
    });
  }
});


// PUT /api/stock/:id - Met à jour un élément
app.put('/api/stock/:id', authenticate, (req, res) => {
  try {
    const itemId = parseInt(req.params.id);
    const itemData = {
      id: itemId,
      nom: req.body.nom,
      quantite: parseInt(req.body.quantite),
      prixAchat: parseFloat(req.body.prixAchat),
      seuilAlerte: parseInt(req.body.seuilAlerte),
      categorie: req.body.categorie,
      user: req.user.userId,
      licenceKey: req.licence.key
    };

    const updatedItem = updateStockItem(itemData, req.licence.key);

    if (!updatedItem) {
      return res.status(404).json({ error: 'Item not found' });
    }

    res.json(updatedItem);
  } catch (error) {
    console.error('PUT /api/stock error:', error);
    res.status(500).json({
      error: 'Failed to update item',
      details: error.message
    });
  }
});

app.delete('/api/stock/:id', authenticate, (req, res) => {
  try {
    const itemId = parseInt(req.params.id);
    deleteStockItem(itemId, req.user.userId, req.licence.key);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});



// ===================== COMMANDES ROUTES =====================
// GET toutes les commandes
app.get('/api/commandes', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const data = loadData('main');
    const commandes = data.data.commandes
      .filter(c => c.licenceKey === licenceKey)
      .map(commande => ({
        ...commande,
        produits: Array.isArray(commande.produits) ? commande.produits : []
      }));
    res.json(commandes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET une commande par ID
app.get('/api/commandes/:id', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const commandeId = parseInt(req.params.id, 10);
    const data = loadData('main');
    const commande = data.data.commandes.find(
      c => c.id === commandeId && c.licenceKey === licenceKey
    );

    if (!commande) {
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    res.json({
      ...commande,
      produits: Array.isArray(commande.produits) ? commande.produits : []
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST nouvelle commande
app.post('/api/commandes/new', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const requiredFields = ['fournisseur', 'nomProduit', 'prix', 'fournisseurEmail'];
    const missingFields = requiredFields.filter(field => !req.body[field]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Champs manquants: ${missingFields.join(', ')}`,
        details: {
          fournisseur: "string",
          nomProduit: "string",
          prix: "number",
          quantite: "number (optionnel, défaut: 1)",
          fournisseurEmail: "string"
        }
      });
    }

    const prixUnitaire = parseFloat(req.body.prix);
    const quantite = parseInt(req.body.quantite) || 1;

    const newCommande = {
      id: Date.now(),
      fournisseur: req.body.fournisseur,
      fournisseurEmail: req.body.fournisseurEmail,
      productName: req.body.nomProduit,
      produits: [{
        nom: req.body.nomProduit,
        quantite,
        prixUnitaire
      }],
      montant: prixUnitaire * quantite,
      statut: "en_attente",
      date: new Date().toISOString(),
      deliveryDate: req.body.deliveryDate || null,
      user: req.user.userId,
      licenceKey
    };

    const data = loadData('main');
    data.data.commandes.push(newCommande);
    saveData('main', data);

    res.status(201).json(newCommande);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// POST valider commande
app.post('/api/commandes/:id/valider', authenticate, (req, res) => {
  try {
    const commandeId = parseInt(req.params.id);
    const commande = validerCommande(commandeId, req.user.userId, req.licence.key);

    if (!commande) {
      return res.status(404).json({ error: "Commande non trouvée" });
    }

    res.json({
      success: true,
      commande,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


// POST annuler commande
app.post('/api/commandes/:id/annuler', authenticate, (req, res) => {
  try {
    const commandeId = parseInt(req.params.id);
    annulerCommande(commandeId, req.user.userId, req.licence.key);

    res.json({ success: true, message: 'Commande annulée' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===================== VENTES ROUTES =====================
app.get('/api/ventes', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const data = loadData();
    const ventes = data.data.ventes
      .filter(vente => vente.licenceKey === licenceKey)
      .map(vente => ({
        ...vente,
      }));
    res.json(ventes || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ventes', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    if (!req.body.recetteId || !req.body.quantite) {
      throw new Error("recetteId et quantite sont requis");
    }

    const newVente = {
      recetteId: parseInt(req.body.recetteId),
      quantite: parseInt(req.body.quantite),
      client: req.body.client || 'anonyme',
      user: req.user.userId,
      licenceKey
    };

    const createdVente = addVente(newVente, licenceKey);
    res.status(201).json(createdVente);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.post('/api/ventes/:id/valider', authenticate, (req, res) => {
  try {
    const venteId = parseInt(req.params.id);
    const { vente, benefice } = validerVente(venteId, req.user.userId, req.licence.key);

    if (!vente) {
      return res.status(404).json({ error: "Vente non trouvée" });
    }

    res.json({
      success: true,
      vente,
      benefice
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});



// ===================== RECETTES ROUTES =====================
app.get('/api/recettes', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const data = loadData();
    const recettesWithFullUrl = data.data.recettes
      .filter(recette => recette.licenceKey === licenceKey)
      .map(recette => ({
        ...recette,
        ingredients: (Array.isArray(recette.ingredients)
          ? recette.ingredients.map(ing => ({
              id: ing.id,
              nom: ing.nom,
              quantite: ing.quantite,
              unite: ing.unite || 'unité(s)'
            }))
          : []),
        image: recette.image
          ? `http://localhost:3001${recette.image}`
          : null
      }));
    res.json(recettesWithFullUrl || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/recettes/:id/update', authenticate, upload.single('image'), (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const recetteId = parseInt(req.params.id);
    let recipeData = req.body.data ? JSON.parse(req.body.data) : req.body;
    const updateStock = req.query.updateStock === 'true';

    recipeData.ingredients = (Array.isArray(recipeData.ingredients) ? recipeData.ingredients : [])
      .map(ing => ({
        id: parseInt(ing.id) || 0,
        nom: ing.nom || 'Inconnu',
        quantite: parseFloat(ing.quantite) || 0,
        unite: ing.unite || 'unité(s)'
      }));

    const data = loadData();
    const recipeIndex = data.data.recettes.findIndex(r => r.id === recetteId && r.licenceKey === licenceKey);

    if (recipeIndex === -1) {
      throw new Error('Recette non trouvée');
    }

    if (updateStock) {
      for (const ing of recipeData.ingredients) {
        const item = data.data.stock.find(i => i.id === ing.id && i.licenceKey === licenceKey);
        if (!item) throw new Error(`Ingrédient ${ing.id} introuvable`);
        if (item.quantite < ing.quantite) {
          throw new Error(`Stock insuffisant pour ${item.nom}`);
        }
      }
    }

    if (req.file) {
      recipeData.image = `/uploads/${req.file.filename}`;
    }

    const oldRecipe = data.data.recettes[recipeIndex];
    data.data.recettes[recipeIndex] = {
      ...oldRecipe,
      ...recipeData,
      prix: parseFloat(recipeData.prix) || oldRecipe.prix,
      licenceKey
    };

    if (updateStock) {
      for (const ing of recipeData.ingredients) {
        const item = data.data.stock.find(i => i.id === ing.id && i.licenceKey === licenceKey);
        item.quantite -= ing.quantite;

        data.data.mouvements.push({
          id: generateId(data.data.mouvements),
          productId: item.id,
          nom: item.nom,
          type: 'modification_recette',
          quantite: -ing.quantite,
          date: new Date().toISOString(),
          details: {
            recetteId,
            recetteNom: recipeData.nom,
            user: req.user.userId
          },
          licenceKey
        });
      }
    }

    saveData(data);

    res.json({
      ...data.data.recettes[recipeIndex],
      image: data.data.recettes[recipeIndex].image
        ? `http://localhost:3001${data.data.recettes[recipeIndex].image}`
        : null
    });

  } catch (error) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/recettes', authenticate, upload.single('image'), (req, res) => {
  const sanitizeIngredients = (ingredients) => {
    return (Array.isArray(ingredients) ? ingredients : [])
      .map(ing => ({
        id: parseInt(ing.id) || 0,
        nom: ing.nom?.trim() || 'Inconnu',
        quantite: parseFloat(ing.quantite) || 0,
        unite: ing.unite?.trim() || 'unité(s)'
      }));
  };

  let recipeData;

  try {
    if (req.body.data) {
      try {
        recipeData = JSON.parse(req.body.data);
      } catch (e) {
        return res.status(400).json({ error: "Format JSON invalide dans req.body.data" });
      }
    } else {
      recipeData = req.body;
    }

    if (typeof recipeData.ingredients === 'string') {
      try {
        recipeData.ingredients = JSON.parse(recipeData.ingredients);
      } catch (e) {
        return res.status(400).json({ error: "Format JSON invalide dans ingredients" });
      }
    }

    if (!recipeData.nom?.trim()) {
      throw new Error("Le nom est requis");
    }

    const licenceKey = req.licence.key;
    const newRecipe = {
      ...recipeData,
      id: generateId(),
      prix: parseFloat(recipeData.prix) || 0,
      ingredients: sanitizeIngredients(recipeData.ingredients),
      image: req.file ? `/uploads/${req.file.filename}` : '',
      user: req.user.userId,
      licenceKey
    };

    if (!Array.isArray(newRecipe.ingredients) || newRecipe.ingredients.length === 0) {
      throw new Error("Au moins un ingrédient valide est requis");
    }

    const invalidIngredient = newRecipe.ingredients.find(
      ing => !ing.nom || isNaN(ing.quantite) || ing.quantite <= 0
    );

    if (invalidIngredient) {
      throw new Error(`Ingrédient invalide: ${invalidIngredient.nom}`);
    }

    const createdRecipe = addRecette(newRecipe, licenceKey);

    res.status(201).json({
      success: true,
      data: {
        ...createdRecipe,
        image: createdRecipe.image ? `${req.protocol}://${req.get('host')}${createdRecipe.image}` : null
      }
    });

  } catch (error) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }

    res.status(400).json({
      success: false,
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

app.delete('/api/recettes/:id', authenticate, async (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const recetteId = parseInt(req.params.id);
    const data = loadData();
    const recetteIndex = data.data.recettes.findIndex(r => r.id === recetteId && r.licenceKey === licenceKey);

    if (recetteIndex === -1) {
      return res.status(404).json({ error: 'Recette non trouvée' });
    }

    deleteRecette(recetteId);
    res.json({ success: true, message: 'Recette supprimée' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===================== MOUVEMENTS ROUTES =====================
// ===================== MOUVEMENTS ROUTES ============>
app.post('/api/mouvements', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const userId = req.user.userId;
    const { nom, produitId, type, quantite, details } = req.body;

    // Validation
    if (!type || quantite === undefined || (!nom && !produitId)) {
      return res.status(400).json({
        error: "Champs requis manquants",
        required: {
          type: ["réapprovisionnement", "diminution", "suppression", "modification"],
          quantite: "number",
          nom_or_produitId: "string|number"
        }
      });
    }

    const data = loadData('main'); // Chargement unique du fichier principal

    // Recherche du produit
    const produit = data.data.stock.find(item => 
      item.licenceKey === licenceKey && 
      (produitId ? item.id === Number(produitId) : item.nom.toLowerCase() === nom.toLowerCase())
    );

    if (!produit) {
      return res.status(404).json({
        error: "Produit non trouvé",
        produitsDisponibles: data.data.stock
          .filter(p => p.licenceKey === licenceKey)
          .map(p => ({ id: p.id, nom: p.nom }))
      });
    }

    // Calcul nouvelle quantité
    const stockBefore = produit.quantite;
    let stockAfter = stockBefore;

    switch (type) {
      case 'réapprovisionnement':
        stockAfter = stockBefore + Number(quantite);
        break;
      case 'diminution':
        stockAfter = Math.max(0, stockBefore - Number(quantite));
        break;
      case 'suppression':
        stockAfter = 0;
        break;
      case 'modification':
        stockAfter = Number(quantite);
        break;
      default:
        return res.status(400).json({ error: "Type de mouvement invalide" });
    }

    // Mise à jour du stock
    produit.quantite = stockAfter;

    // Création du mouvement
    const newMouvement = {
      id: generateId(data.data.mouvements),
      produitId: produit.id,
      nom: produit.nom,
      type,
      quantite: type === 'réapprovisionnement' ? Number(quantite) : -Number(quantite),
      date: new Date().toISOString(),
      details: {
        ...details,
        user: userId,
        stockBefore,
        stockAfter
      },
      licenceKey
    };

    // Ajout aux mouvements
    data.data.mouvements.push(newMouvement);

    // Sauvegarde unique
    saveData('main', data);

    res.status(201).json({
      success: true,
      mouvement: newMouvement,
      stock: {
        id: produit.id,
        nom: produit.nom,
        nouvelleQuantite: stockAfter
      }
    });

  } catch (error) {
    console.error("Erreur mouvements:", error);
    res.status(500).json({
      error: "Erreur de traitement",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Ajouter dans votre backend
app.post('/api/recettes-avec-stock', authenticate, upload.single('image'), async (req, res) => {
  try {
    const licenceKey = req.licence.key;
    let recipeData;
    try {
      recipeData = req.body.data ? JSON.parse(req.body.data) : req.body;
    } catch (e) {
      recipeData = req.body;
    }

    if (!recipeData.nom || !recipeData.ingredients) {
      throw new Error("Nom et ingrédients sont requis");
    }

    const ingredients = Array.isArray(recipeData.ingredients)
      ? recipeData.ingredients
      : JSON.parse(recipeData.ingredients);

    const newRecipe = {
      ...recipeData,
      prix: parseFloat(recipeData.prix) || 0,
      ingredients: ingredients.map(ing => ({
        ...ing,
        id: parseInt(ing.id),
        quantite: parseFloat(ing.quantite)
      })),
      image: req.file ? `/uploads/${req.file.filename}` : null,
      user: req.user.userId,
      licenceKey
    };

    const createdRecipe = addRecetteWithStockUpdate(newRecipe, licenceKey);
    res.status(201).json({
      ...createdRecipe,
      image: createdRecipe.image ? `http://localhost:3000${createdRecipe.image}` : null
    });
  } catch (error) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(400).json({ error: error.message });
  }
});


// ===================== ALERTES ROUTES =====================
app.get('/api/alertes', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const alerts = getStockAlerts(licenceKey);
    res.json(alerts || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===================== RAPPORTS ROUTES ==============>
app.get('/api/rapports', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const data = loadData('main'); // Spécifier le fichier 'main'
    
    // Initialiser les rapports s'ils n'existent pas
    if (!data.data.rapports) {
      data.data.rapports = {
        ventes: [],
        depenses: [],
        benefices: []
      };
    }

    const rapports = {
      ventes: (data.data.rapports.ventes || [])
        .filter(vente => vente.licenceKey === licenceKey)
        .map(v => ({ ...v })),
      depenses: (data.data.rapports.depenses || [])
        .filter(depense => depense.licenceKey === licenceKey)
        .map(d => ({ ...d })),
      benefices: (data.data.rapports.benefices || [])
        .filter(benefice => benefice.licenceKey === licenceKey)
        .map(b => ({ ...b }))
    };

    res.json(rapports);
  } catch (error) {
    console.error('Erreur dans /api/rapports:', error);
    res.status(500).json({ 
      error: 'Erreur lors de la récupération des rapports',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Staff routes (SuperAdmin)
app.get('/api/staff', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const mainData = loadData('main');
    const staffMembers = (mainData.data.staff || [])
      .filter(s => s.licenceKey === licenceKey)
      .map(member => ({
        id: member.id,
        email: member.email,
        role: member.role,
        createdAt: member.createdAt
      }));

    res.json({
      success: true,
      count: staffMembers.length,
      staff: staffMembers
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Erreur de récupération du staff',
      details: error.message
    });
  }
});


app.post('/api/staff', authenticate, async (req, res) => {
  try {
    const { email, password, role, adminPassword } = req.body;
    const licenceKey = req.licence.key;
    const creatorId = req.user.userId;

    // 1. Trouver le superAdmin connecté
    const usersData = loadData('users');
    const creator = (Array.isArray(usersData) ? usersData : usersData.users || []).find(u => u.id === creatorId);

    console.log('Créateur trouvé :', creator);

    if (!creator || creator.role !== 'superAdmin') {
      return res.status(403).json({
        error: 'Action réservée aux super-administrateurs',
        code: 'ADMIN_ACCESS_REQUIRED'
      });
    }

    // 2. Vérifier le mot de passe admin
    const isValid = await bcrypt.compare(adminPassword, creator.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Mot de passe administrateur incorrect' });
    }

    // 3. Vérifier l'unicité de l'email
    const mainData = loadData('main');
    const existingStaff = (mainData.data?.staff || []).some(s => s.email === email);
    const existingUser = (Array.isArray(usersData) ? usersData : usersData.users || []).some(u => u.email === email);

    if (existingStaff || existingUser) {
      return res.status(400).json({
        error: 'Email déjà utilisé',
        code: 'EMAIL_EXISTS'
      });
    }

    // 4. Créer le staff
    const newStaff = {
      id: generateId(),
      email,
      passwordHash: await hashPassword(password),
      role: role || 'staff',
      licenceKey,
      createdAt: new Date().toISOString(),
      createdBy: creatorId
    };

    // 5. Sauvegarder
    mainData.data.staff = [...(mainData.data.staff || []), newStaff];
    saveData('main', mainData);

    res.status(201).json({
      success: true,
      staff: {
        id: newStaff.id,
        email: newStaff.email,
        role: newStaff.role
      }
    });

  } catch (error) {
    console.error('[STAFF CREATION ERROR]', error);
    res.status(500).json({
      error: 'Erreur lors de la création du staff',
      details: error.message
    });
  }
});

app.delete('/api/staff/:id', authenticate, async (req, res) => {
  try {
    const licenceKey = req.headers['x-licence-key'];
    const staffId = parseInt(req.params.id);
    const userId = req.user.userId;
    const { adminPassword } = req.body; // Récupérer le mot de passe de l'administrateur depuis le corps de la requête

    const usersData = loadData('users');
    const users = Array.isArray(usersData) ? usersData : usersData.users || [];

    const currentUser = users.find(u => u.id === userId);

    console.log('Utilisateur actuel (pour suppression) :', currentUser);

    if (!currentUser || currentUser.role !== 'superAdmin') {
      return res.status(403).json({
        error: 'Action non autorisée : superAdmin requis',
        code: 'ADMIN_ACCESS_REQUIRED'
      });
    }

    // Vérifier le mot de passe de l'administrateur
    const isAdminPasswordValid = await bcrypt.compare(adminPassword, currentUser.passwordHash);
    if (!isAdminPasswordValid) {
      return res.status(403).json({
        error: 'Mot de passe administrateur incorrect',
        code: 'INVALID_ADMIN_PASSWORD'
      });
    }

    // Supprimer le staff dans le fichier main
    const mainData = loadData('main');
    const originalStaffList = mainData.data?.staff || [];
    const updatedStaffList = originalStaffList.filter(s => s.id !== staffId || s.licenceKey !== licenceKey);

    if (originalStaffList.length === updatedStaffList.length) {
      return res.status(404).json({
        error: "Aucun membre du staff correspondant trouvé pour suppression"
      });
    }

    mainData.data.staff = updatedStaffList;
    saveData('main', mainData);

    res.json({ success: true });
  } catch (error) {
    console.error('[DELETE STAFF ERROR]', error);
    res.status(500).json({
      error: 'Erreur lors de la suppression du staff',
      details: error.message
    });
  }
});

// Version corrigée (notez 'app.post' au lieu de 'pp.post')
app.post('/api/verify-password', async (req, res) => {
  try {
    const { password, hash } = req.body;
    if (!password || !hash) {
      return res.status(400).json({ error: 'Mot de passe et hash requis' });
    }

    const valid = await verifyPassword(password, hash);
    res.json({ valid });
  } catch (error) {
    console.error('Verify password error:', error);
    res.status(500).json({ error: 'Erreur de vérification du mot de passe' });
  }
});


// ===================== HISTORIQUE ROUTES =====================
app.get('/api/history', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    const data = loadData('main'); // Assurez-vous que 'main' est le bon fileKey

    const actionMap = {
      'ADD_STOCK_ITEM': 'STOCK_ADD',
      'UPDATE_STOCK_ITEM': 'STOCK_UPDATE',
      'DELETE_STOCK_ITEM': 'STOCK_DELETE',
      'ADD_COMMANDE': 'ORDER_ADD',
      'VALIDER_COMMANDE': 'ORDER_VALIDATE',
      'ANNULER_COMMANDE': 'ORDER_CANCEL',
      'ADD_RECETTE': 'RECIPE_ADD',
      'ADD_RECETTE_WITH_STOCK_UPDATE': 'RECIPE_USE_STOCK',
      'DELETE_RECETTE': 'RECIPE_DELETE',
      'ADD_VENTE': 'SALE_CREATE',
      'VALIDER_VENTE': 'SALE_COMPLETE',
      'USER_CREATED': 'USER_CREATE',
      'USER_LICENCE_UPDATED': 'USER_UPDATE'
    };

    const usersMap = data.data.users.reduce((acc, user) => {
      if (user.licenceKey === licenceKey) {
        acc[user.id] = user.email;
      }
      return acc;
    }, {});

    const productsMap = data.data.stock.reduce((acc, product) => {
      if (product.licenceKey === licenceKey) {
        acc[product.id] = product.nom;
      }
      return acc;
    }, {});

    const recipesMap = data.data.recettes.reduce((acc, recipe) => {
      if (recipe.licenceKey === licenceKey) {
        acc[recipe.id] = recipe.nom;
      }
      return acc;
    }, {});

    const suppliersMap = {};
    data.data.commandes.forEach(cmd => {
      if (cmd.fournisseur && cmd.id && cmd.licenceKey === licenceKey) {
        suppliersMap[cmd.id] = cmd.fournisseur;
      }
    });

    const completeHistory = data.logs.actions
      .filter(log => log.licenceKey === licenceKey)
      .map(log => {
        const baseEntry = {
          id: log.id,
          timestamp: log.timestamp,
          date: new Date(log.timestamp).toLocaleString('fr-FR'),
          actionType: actionMap[log.action] || log.action,
          user: usersMap[log.user] || log.user || 'system'
        };

        switch (log.action) {
          case 'ADD_STOCK_ITEM':
            return {
              ...baseEntry,
              details: {
                productId: data.data.stock.find(p => p.id === log.details.productId)?.id,
                nom: log.details.nom,
                quantite: log.details.quantite,
                prixAchat: log.details.prixAchat,
                categorie: log.details.categorie,
                seuilAlerte: log.details.seuilAlerte
              }
            };

          case 'UPDATE_STOCK_ITEM':
            return {
              ...baseEntry,
              details: {
                productId: data.data.stock.find(p => p.id === log.details.productId)?.id,
                nom: log.details.nom,
                ancienneQuantite: log.details.ancienneQuantite,
                nouvelleQuantite: log.details.nouvelleQuantite,
                difference: log.details.nouvelleQuantite - log.details.ancienneQuantite,
                prixAchat: log.details.prixAchat
              }
            };

          case 'DELETE_STOCK_ITEM':
            return {
              ...baseEntry,
              details: {
                nom: log.details.nom,
                derniereQuantite: log.details.derniereQuantite
              }
            };

          case 'ADD_COMMANDE':
            const addedCmd = data.data.commandes.find(c => c.id === log.details.commandeId);
            return {
              ...baseEntry,
              details: {
                commandeId: addedCmd?.id || log.details.commandeId,
                fournisseur: addedCmd?.fournisseur || log.details.fournisseur,
                fournisseurEmail: addedCmd?.fournisseurEmail || log.details.fournisseurEmail,
                produits: addedCmd?.produits || log.details.produits,
                montantTotal: addedCmd?.montant || log.details.montantTotal,
                statut: addedCmd?.statut || 'en_attente',
                dateCreation: addedCmd?.date || log.timestamp
              }
            };

          case 'VALIDER_COMMANDE':
            const validatedCmd = data.data.commandes.find(c => c.id === log.details.commandeId);
            return {
              ...baseEntry,
              details: {
                commandeId: validatedCmd?.id || log.details.commandeId,
                fournisseur: validatedCmd?.fournisseur || log.details.fournisseur,
                produits: validatedCmd?.produits.map(p => ({
                  nom: p.nom,
                  quantite: p.quantite,
                  prixUnitaire: p.prixUnitaire,
                  montant: p.quantite * p.prixUnitaire,
                  stockAfter: data.data.stock.find(s => s.id === p.id)?.quantite
                })) || log.details.produits,
                montantTotal: validatedCmd?.montant || log.details.montantTotal,
                dateValidation: validatedCmd?.dateValidation || log.timestamp,
                mouvementsStock: data.data.mouvements
                  .filter(m => m.details?.commandeId === log.details.commandeId)
                  .map(m => ({
                    productId: m.productId,
                    nom: m.nom,
                    quantite: m.quantite,
                    type: m.type,
                    date: m.date
                  }))
              }
            };

          case 'ANNULER_COMMANDE':
            return {
              ...baseEntry,
              details: {
                commandeId: log.details.commandeId,
                raison: log.details.raison || 'manuelle'
              }
            };

          case 'ADD_RECETTE':
            const addedRecipe = data.data.recettes.find(r => r.id === log.details.recetteId);
            return {
              ...baseEntry,
              details: {
                recetteId: addedRecipe?.id || log.details.recetteId,
                nom: addedRecipe?.nom || log.details.nom,
                prix: addedRecipe?.prix || log.details.prix,
                ingredients: addedRecipe?.ingredients?.map(ing => ({
                  id: ing.id,
                  nom: productsMap[ing.id] || ing.nom,
                  quantite: ing.quantite
                })) || log.details.ingredients,
                image: addedRecipe?.image
              }
            };

          case 'ADD_RECETTE_WITH_STOCK_UPDATE':
            const recipeWithStock = data.data.recettes.find(r => r.id === log.details.recetteId);
            return {
              ...baseEntry,
              details: {
                recetteId: recipeWithStock?.id || log.details.recetteId,
                nom: recipeWithStock?.nom || log.details.nom,
                ingredients: recipeWithStock?.ingredients?.map(ing => ({
                  id: ing.id,
                  nom: productsMap[ing.id] || ing.nom,
                  quantite: ing.quantite,
                  stockAvant: data.data.stock.find(s => s.id === ing.id)?.quantite,
                  stockApres: data.data.stock.find(s => s.id === ing.id)?.quantite
                })) || log.details.ingredients,
                mouvementsAssocies: data.data.mouvements
                  .filter(m => m.details?.recetteId === log.details.recetteId)
                  .map(m => ({
                    productId: m.productId,
                    nom: m.nom,
                    quantite: m.quantite,
                    type: m.type
                  }))
              }
            };

          case 'DELETE_RECETTE':
            return {
              ...baseEntry,
              details: {
                recetteId: log.details.recetteId,
                nom: log.details.nom
              }
            };

          case 'ADD_VENTE':
            const addedSale = data.data.ventes.find(v => v.id === log.details.venteId);
            return {
              ...baseEntry,
              details: {
                venteId: addedSale?.id || log.details.venteId,
                recetteId: addedSale?.recetteId,
                recetteNom: recipesMap[addedSale?.recetteId],
                quantite: addedSale?.quantite || log.details.quantite,
                prixTotal: addedSale?.prixTotal || log.details.prixTotal,
                client: addedSale?.client || log.details.client,
                statut: addedSale?.statut || 'en_attente'
              }
            };

          case 'VALIDER_VENTE':
            const validatedSale = data.data.ventes.find(v => v.id === log.details.venteId);
            return {
              ...baseEntry,
              details: {
                venteId: validatedSale?.id || log.details.venteId,
                recetteId: validatedSale?.recetteId,
                recetteNom: recipesMap[validatedSale?.recetteId],
                quantite: validatedSale?.quantite || log.details.quantite,
                prixTotal: validatedSale?.prixTotal || log.details.prixTotal,
                coutTotal: validatedSale?.coutTotal || log.details.coutTotal,
                benefice: validatedSale?.benefice || log.details.benefice,
                ingredientsUtilises: validatedSale?.recette?.ingredients?.map(ing => ({
                  id: ing.id,
                  nom: productsMap[ing.id],
                  quantite: ing.quantite * validatedSale?.quantite,
                  prixUnitaire: data.data.stock.find(s => s.id === ing.id)?.prixAchat
                })) || [],
                mouvementsStock: data.data.mouvements
                  .filter(m => m.details?.venteId === log.details.venteId)
                  .map(m => ({
                    productId: m.productId,
                    nom: m.nom,
                    quantite: m.quantite,
                    type: m.type
                  }))
              }
            };

          case 'USER_CREATED':
            return {
              ...baseEntry,
              details: {
                userId: log.details.userId,
                email: log.details.email,
                role: log.details.role
              }
            };

          default:
            return {
              ...baseEntry,
              details: log.details
            };
        }
      }).reverse();

    res.json({
      success: true,
      count: completeHistory.length,
      history: completeHistory
    });
  } catch (error) {
    console.error('Erreur historique:', error);
    res.status(500).json({
      error: "Erreur lors de la récupération de l'historique",
      details: error.message
    });
  }
});


app.get('/api/debug', authenticate, (req, res) => {
  const data = loadData();
  res.json({
    stock: data.data.stock.some(item => !item.licenceKey),
    rapports: data.data.rapports.ventes.some(v => !v.licenceKey),
    historique: data.logs.actions.some(a => !a.licenceKey)
  });
});


// ===================== INITIALISATION ROUTE =====================
app.post('/api/init', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence.key;
    saveData(initDataStructure(licenceKey));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.get('/', (req, res) => {
  res.send('Bienvenue sur le backend de gestion de stock');
});

// Toutes vos autres routes API viendraient ici...
// (vous devriez avoir toutes vos routes définies avant)

// Error handling middleware (doit être placé APRÈS toutes les routes)
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint non trouvé' });
});

// Server startup
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend démarré sur http://0.0.0.0:${PORT}`);
  console.log('Endpoints disponibles:');
  console.log('• GET    /api/licence/validate');
  console.log('• POST   /api/master/licences/generate');
  console.log('• POST   /api/master/licences/revoke (master)');
  console.log('• POST   /api/master/licences/mark-used (master)');
  console.log('• GET    /api/master/licences (master)');
  console.log('• POST   /api/dashboard/licences/generate');
  console.log('• POST   /api/setup');
  console.log('• POST   /api/login');
  console.log('• POST   /api/verify-password');
  console.log('• POST   /api/reset-password');
  console.log('• POST   /api/users');
  console.log('• DELETE /api/users/:id');
  console.log('• GET    /api/staff');
  console.log('• POST   /api/staff');
  console.log('• DELETE /api/staff/:id');
  console.log('• GET    /api/stock');
  console.log('• POST   /api/stock');
  console.log('• PUT    /api/stock/:id');
  console.log('• DELETE /api/stock/:id');
  console.log('• GET    /api/commandes');
  console.log('• POST   /api/commandes/new');
  console.log('• POST   /api/commandes/:id/valider');
  console.log('• POST   /api/commandes/:id/annuler');
  console.log('• GET    /api/ventes');
  console.log('• POST   /api/ventes');
  console.log('• POST   /api/ventes/:id/valider');
  console.log('• GET    /api/recettes');
  console.log('• POST   /api/recettes');
  console.log('• POST   /api/recettes-avec-stock');
  console.log('• DELETE /api/recettes/:id');
  console.log('• POST   /api/orders/start');
  console.log('• GET    /api/mouvements');
  console.log('• GET    /api/alertes');
  console.log('• GET    /api/rapports');
  console.log('• GET    /api/staff');
  console.log('• POST   /api/staff');
  console.log('• POST   /api/verify-password');
  console.log('• DELETE /api/staff/:id');
  console.log('• GET    /api/history');
  console.log('• POST   /api/init');
});
