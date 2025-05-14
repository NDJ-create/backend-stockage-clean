const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

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
  allowedHeaders: ['Content-Type', 'Authorization', 'x-licence-key', 'x-master-key']
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

// Authentication middleware

// Middleware d'authentification JWT (conservé tel quel)
function authenticate(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Token manquant',
      code: 'MISSING_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Erreur de vérification du token:', {
      error: err.message,
      token: token.substring(0, 10) + '...'
    });
    res.status(401).json({ 
      error: 'Token invalide',
      code: 'INVALID_TOKEN'
    });
  }
}

// Nouveau middleware masterLicenceRequired (fusionné et amélioré)
function masterLicenceRequired(req, res, next) {
  // 1. Récupération de la clé de licence (toutes méthodes supportées)
  const licenceKey = req.headers['x-licence-key'] || 
                   req.headers['x-master-key'] || 
                   (req.headers['authorization']?.startsWith('Licence ') ? 
                    req.headers['authorization'].split(' ')[1] : null) ||
                   req.body?.key;

  // 2. Journalisation de debug
  console.log('=== MASTER AUTH DEBUG ===\nClé reçue:', licenceKey);

  // 3. Vérification de la clé master globale (backdoor)
  if (licenceKey === process.env.MASTER_API_KEY) {
    console.log('Accès master via clé globale');
    return next();
  }

  // 4. Validation standard de la licence
  try {
    if (!licenceKey) {
      throw new Error('Aucune clé de licence fournie');
    }

    const validation = validateLicence(licenceKey);
    
    // Debug: Affiche le résultat complet de la validation
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

    // Stockage dans la requête pour usage ultérieur
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
function licenceCheckMiddleware(req, res, next) {
  // 1. Routes exemptées (ne nécessitent PAS de licence)
  const exemptedRoutes = [
    '/api/licence/validate',
    '/api/setup',
    '/api/login',
    '/api/reset-password'
  ];

  // 2. Vérification des routes exemptées
  if (exemptedRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }

  // 3. Récupération de la clé de licence
  const licenceKey = req.headers['x-licence-key'];

  // 4. Debug (optionnel)
  console.log('[Licence Check] Route:', req.path, 'Key:', licenceKey ? `${licenceKey.substring(0, 3)}...` : 'none');

  // 5. Vérification Master Key (backdoor)
  if (licenceKey === MASTER_API_KEY) {
    console.log('[Licence Check] Accès master autorisé');
    return next();
  }

  // 6. Validation standard
  try {
    if (!licenceKey) {
      throw new Error('Licence requise. Header manquant: x-licence-key');
    }

    const validation = validateLicence(licenceKey);
    
    if (!validation.valid) {
      throw new Error(validation.reason || 'Licence invalide ou expirée');
    }

    // 7. Attache les données de licence à la requête pour usage ultérieur
    req.licence = {
      key: licenceKey,
      ...validation.licenceData
    };

    next();
  } catch (error) {
    // 8. Gestion des erreurs
    console.error('[Licence Check] Erreur:', error.message);
    return res.status(403).json({
      error: 'Accès refusé',
      details: error.message,
      code: 'LICENCE_CHECK_FAILED',
      solution: 'Vérifiez votre clé de licence ou contactez le support'
    });
  }
}


// ===================== ROUTES LICENCE =====================
app.post('/api/licence/validate', (req, res) => {
  try {
    const { key } = req.body;
    console.log(`=== DEBUG VALIDATION START ===\nClé reçue: ${key.substring(0, 3)}...${key.substring(-3)}`);

    // 1. Validation Master Key
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
      console.log('Validation licence (MASTER):', { ...response, key: '***' });
      return res.json(response);
    }

    // 2. Validation Standard
    const validation = validateLicence(key);
    const response = {
      valid: validation.valid,
      isMaster: validation.isMaster,
      isExpired: validation.isExpired || false,
      expiresAt: validation.expiresAt,
      clientInfo: validation.licence?.clientInfo || null,
      isActive: validation.licence?.isActive !== false,
      ...(!validation.valid && { reason: validation.reason || 'Invalid licence key' })
    };

    console.log('Validation licence:', { 
      ...response, 
      key: key.substring(0, 3) + '...' + key.substring(-3),
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

    const newLicence = generateLicence(clientInfo, 'system', durationType);

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

app.post('/api/master/licences/generate', masterLicenceRequired, (req, res) => {
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

app.post('/api/master/licences/generate', masterLicenceRequired, (req, res) => {
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
    const { status } = req.query; // Récupère le paramètre de filtrage
    const licenceData = loadLicenceData();
    
    // Formatage de base
    let formattedLicences = licenceData.licences.map(licence => ({
      key: licence.key,
      clientInfo: licence.clientInfo || {},
      createdAt: licence.createdAt,
      expiresAt: licence.expiresAt,
      durationType: licence.durationType || '1y',
      isActive: licence.isActive !== false, // Default true si non défini
      revoked: !!licence.revoked, // Force boolean
      revokedAt: licence.revokedAt,
      revokedReason: licence.revokedReason,
      usedBy: licence.usedBy || null,
      isExpired: licence.expiresAt && new Date(licence.expiresAt) < new Date()
    }));

    // Filtrage avancé
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

    // Calcul des compteurs
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
      expiredCount: formattedLicences.filter(l => l.isExpired && !l.revoked).length
    });

  } catch (error) {
    console.error('Erreur licence:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({
      error: 'Erreur de chargement des licences',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});



// ===================== ROUTES UTILISATEUR =====================

app.post('/api/setup', licenceCheckMiddleware, async (req, res) => {
  try {
    const data = loadData();
    if (data.data.users.length > 0) {
      return res.status(400).json({ error: 'Le système est déjà configuré.' });
    }

    const { email, password, secretQuestion, secretAnswer } = req.body;
    if (!email || !password || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ error: 'Email, mot de passe, question secrète et réponse secrète sont requis.' });
    }

    const hashedPassword = await hashPassword(password);
    const superAdmin = {
      id: generateId(data.data.users),
      email,
      passwordHash: hashedPassword,
      role: 'superAdmin',
      secretQuestion,
      secretAnswer,
      createdAt: new Date().toISOString()
    };

    data.data.users.push(superAdmin);
    saveData(data);

    const token = jwt.sign(
      { userId: superAdmin.id, role: superAdmin.role },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      user: {
        id: superAdmin.id,
        email: superAdmin.email,
        role: superAdmin.role
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.post('/api/login', licenceCheckMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    const data = loadData();
    const user = data.data.users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Identifiants incorrects' });

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Identifiants incorrects' });

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===================== ROUTES SÉCURISÉES =====================
app.post('/api/dashboard/licences/generate', authenticate, masterLicenceRequired, (req, res) => {
  try {
    const { clientInfo = {}, durationType = '1y' } = req.body;

    if (!clientInfo.name || !clientInfo.email) {
      return res.status(400).json({
        error: 'Informations client incomplètes',
        required: ['clientInfo.name', 'clientInfo.email']
      });
    }

    const newLicence = generateLicence(clientInfo, req.user.userId, durationType);

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

app.get('/api/stock', authenticate, (req, res) => {
  try {
    const data = loadData();
    const stockWithAlerts = data.data.stock.map(item => ({
      ...item,
      alerte: item.quantite <= (item.seuilAlerte || 5)
    }));
    res.json(stockWithAlerts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/stock', authenticate, (req, res) => {
  try {
    const newItem = {
      ...req.body,
      quantite: parseInt(req.body.quantite) || 0,
      seuilAlerte: parseInt(req.body.seuilAlerte) || 5,
      prixAchat: parseFloat(req.body.prixAchat) || 0,
      user: req.user.userId
    };
    const createdItem = addStockItem(newItem);
    res.status(201).json(createdItem);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/stock/:id', authenticate, (req, res) => {
  try {
    const updatedItem = {
      ...req.body,
      id: parseInt(req.params.id),
      quantite: parseInt(req.body.quantite) || 0,
      prixAchat: parseFloat(req.body.prixAchat) || 0,
      user: req.user.userId
    };
    updateStockItem(updatedItem);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/stock/:id', authenticate, (req, res) => {
  try {
    deleteStockItem(parseInt(req.params.id));
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===================== COMMANDES ROUTES =====================
app.get('/api/commandes', authenticate, (req, res) => {
  try {
    const data = loadData();
    const commandes = data.data.commandes.map(commande => {
      // Vérifiez si la propriété `produits` existe et est un tableau
      const produits = commande.produits && Array.isArray(commande.produits)
        ? commande.produits.map(produit => ({
            ...produit,
          }))
        : [];

      return {
        ...commande,
        produits
      };
    });

    res.json(commandes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



app.get('/api/commandes/:id', authenticate, (req, res) => {
  try {
    const data = loadData();
    const commande = data.data.commandes.find(c => c.id === parseInt(req.params.id));
    if (!commande) return res.status(404).json({ error: 'Commande non trouvée' });

    const commandeWithCFA = {
      ...commande,
      produits: commande.produits.map(produit => ({
        ...produit,
      }))
    };

    res.json(commandeWithCFA);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/commandes/new', authenticate, (req, res) => {
  try {
    const requiredFields = ['fournisseur', 'nomProduit', 'prix'];
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
        quantite: quantite,
        prixUnitaire: prixUnitaire
      }],
      montant: prixUnitaire * quantite,
      statut: "en_attente",
      date: new Date().toISOString(),
      deliveryDate: req.body.deliveryDate || null,
      user: req.user.userId
    };

    const createdCommande = addCommande(newCommande);
    res.status(201).json(createdCommande);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/commandes/:id/valider', authenticate, (req, res) => {
  try {
    const data = loadData();
    const commandeIndex = data.data.commandes.findIndex(c => c.id === parseInt(req.params.id));

    if (commandeIndex === -1) {
      return res.status(404).json({ error: "Commande non trouvée" });
    }

    const commande = data.data.commandes[commandeIndex];

    if (commande.statut === 'validée') {
      return res.status(400).json({ error: "Commande déjà validée" });
    }

    commande.statut = 'validée';
    commande.dateValidation = new Date().toISOString();

    commande.produits.forEach(produit => {
      let stockItem = data.data.stock.find(item => item.nom === produit.nom);

      if (!stockItem) {
        stockItem = {
          id: data.data.stock.length > 0 ? Math.max(...data.data.stock.map(item => item.id)) + 1 : 1,
          nom: produit.nom,
          quantite: 0,
          prixAchat: produit.prixUnitaire,
          seuilAlerte: 5,
          categorie: 'nouveau',
          dateAjout: new Date().toISOString()
        };
        data.data.stock.push(stockItem);
      }

      stockItem.quantite += produit.quantite;

      data.data.mouvements.push({
        id: data.data.mouvements.length > 0 ? Math.max(...data.data.mouvements.map(m => m.id)) + 1 : 1,
        productId: stockItem.id,
        nom: stockItem.nom,
        type: 'réapprovisionnement',
        quantite: produit.quantite,
        date: new Date().toISOString(),
        details: {
          source: 'commande',
          commandeId: commande.id,
          prixUnitaire: produit.prixUnitaire
        }
      });
    });

    data.data.rapports.depenses.push({
      id: generateId(data.data.rapports.depenses),
      commandeId: commande.id,
      montant: commande.montant,
      date: new Date().toISOString()
    });

    saveData(data);
    res.json({
      success: true,
      commande: commande,
      stock: data.data.stock.find(item => item.nom === commande.productName)
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/commandes/:id/annuler', authenticate, (req, res) => {
  try {
    const commandeId = parseInt(req.params.id);
    annulerCommande(commandeId);
    res.json({ success: true, message: 'Commande annulée' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===================== VENTES ROUTES =====================

app.get('/api/ventes', authenticate, (req, res) => {
  try {
    const data = loadData();
    const ventes = data.data.ventes.map(vente => ({
      ...vente,
    }));
    res.json(ventes || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ventes', authenticate, (req, res) => {
  try {
    if (!req.body.recetteId || !req.body.quantite) {
      throw new Error("recetteId et quantite sont requis");
    }

    const newVente = {
      id: Date.now(),
      recetteId: parseInt(req.body.recetteId),
      quantite: parseInt(req.body.quantite),
      date: new Date().toISOString(),
      statut: 'en_attente',
      client: req.body.client || 'anonyme',
      user: req.user.userId
    };

    const createdVente = addVente(newVente);
    res.status(201).json(createdVente);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/ventes/:id/valider', authenticate, (req, res) => {
  try {
    const data = loadData();
    const vente = data.data.ventes.find(v => v.id === parseInt(req.params.id));

    if (!vente) {
      return res.status(404).json({ error: "Vente non trouvée" });
    }

    const recette = data.data.recettes.find(r => r.id === vente.recetteId);
    if (!recette) {
      return res.status(400).json({ error: "Recette introuvable" });
    }

    let coutTotal = 0;
    let beneficeTotal = 0;

    recette.ingredients.forEach(ingredient => {
      const stockItem = data.data.stock.find(item => item.id === ingredient.id);
      if (stockItem) {
        coutTotal += stockItem.prixAchat * ingredient.quantite;
      }
    });

    beneficeTotal = (recette.prix * vente.quantite) - coutTotal;

    recette.ingredients.forEach(ingredient => {
      const stockItem = data.data.stock.find(item => item.id === ingredient.id);
      if (stockItem) {
        stockItem.quantite -= ingredient.quantite * vente.quantite;

        data.data.mouvements.push({
          id: data.data.mouvements.length > 0 ? Math.max(...data.data.mouvements.map(m => m.id)) + 1 : 1,
          productId: ingredient.id,
          nom: stockItem.nom,
          type: 'vente',
          quantite: -(ingredient.quantite * vente.quantite),
          date: new Date().toISOString(),
          details: {
            venteId: vente.id,
            recetteId: recette.id,
            prixAchat: stockItem.prixAchat
          }
        });
      }
    });

    vente.statut = 'validée';
    vente.dateValidation = new Date().toISOString();
    vente.coutTotal = coutTotal;
    vente.benefice = beneficeTotal;

    data.data.rapports.ventes.push({
      id: generateId(data.data.rapports.ventes),
      venteId: vente.id,
      montant: recette.prix * vente.quantite,
      date: new Date().toISOString()
    });

    data.data.rapports.benefices.push({
      id: generateId(data.data.rapports.benefices),
      venteId: vente.id,
      montant: beneficeTotal,
      date: new Date().toISOString()
    });

    saveData(data);
    res.json({
      success: true,
      vente: vente,
      benefice: beneficeTotal
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===================== RECETTES ROUTES =====================
app.get('/api/recettes', authenticate, (req, res) => {
  try {
    const data = loadData();
    const recettesWithFullUrl = data.data.recettes.map(recette => ({
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


// Modification de recette (avec option de mise à jour du stock)
app.put('/api/recettes/:id/update', authenticate, upload.single('image'), async (req, res) => {
  try {
    const recetteId = parseInt(req.params.id);
    let recipeData = req.body.data ? JSON.parse(req.body.data) : req.body;
    const updateStock = req.query.updateStock === 'true';

    // Sanitize ingredients
    recipeData.ingredients = (Array.isArray(recipeData.ingredients) ? recipeData.ingredients : [])
      .map(ing => ({
        id: parseInt(ing.id) || 0,
        nom: ing.nom || 'Inconnu',
        quantite: parseFloat(ing.quantite) || 0,
        unite: ing.unite || 'unité(s)'
      }));

    // Load data
    const data = loadData();
    const recipeIndex = data.data.recettes.findIndex(r => r.id === recetteId);
    
    if (recipeIndex === -1) {
      throw new Error('Recette non trouvée');
    }

    // Vérification stock si nécessaire
    if (updateStock) {
      for (const ing of recipeData.ingredients) {
        const item = data.data.stock.find(i => i.id === ing.id);
        if (!item) throw new Error(`Ingrédient ${ing.id} non trouvé`);
        if (item.quantite < ing.quantite) {
          throw new Error(`Stock insuffisant pour ${item.nom}`);
        }
      }
    }

    // Update image if new file uploaded
    if (req.file) {
      recipeData.image = `/uploads/${req.file.filename}`;
    }

    // Update recipe
    const oldRecipe = data.data.recettes[recipeIndex];
    data.data.recettes[recipeIndex] = {
      ...oldRecipe,
      ...recipeData,
      prix: parseFloat(recipeData.prix) || oldRecipe.prix
    };

    // Update stock if requested
    if (updateStock) {
      for (const ing of recipeData.ingredients) {
        const item = data.data.stock.find(i => i.id === ing.id);
        item.quantite -= ing.quantite;
        
        // Log movement
        data.data.mouvements.push({
          id: generateId(data.data.mouvements),
          productId: item.id,
          type: 'modification_recette',
          quantite: -ing.quantite,
          date: new Date().toISOString(),
          details: {
            recetteId,
            recetteNom: recipeData.nom,
            user: req.user.userId
          }
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


app.post('/api/recettes', authenticate, upload.single('image'), async (req, res) => {
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
    // Gestion du payload (JSON ou FormData)
    if (req.body.data) {
      try {
        recipeData = JSON.parse(req.body.data);
      } catch (e) {
        return res.status(400).json({ error: "Format JSON invalide dans req.body.data" });
      }
    } else {
      recipeData = req.body;
    }

    // Gestion des ingrédients (string JSON ou objet)
    if (typeof recipeData.ingredients === 'string') {
      try {
        recipeData.ingredients = JSON.parse(recipeData.ingredients);
      } catch (e) {
        return res.status(400).json({ error: "Format JSON invalide pour les ingrédients" });
      }
    }

    // Validation requise
    if (!recipeData.nom?.trim()) {
      throw new Error("Le nom est requis");
    }

    // Construction de l'objet final
    const newRecipe = {
      ...recipeData,
      id: generateId(),
      prix: parseFloat(recipeData.prix) || 0,
      ingredients: sanitizeIngredients(recipeData.ingredients),
      image: req.file ? `/uploads/${req.file.filename}` : null,
      user: req.user.userId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Validation supplémentaire des ingrédients
    if (!Array.isArray(newRecipe.ingredients) || newRecipe.ingredients.length === 0) {
      throw new Error("Au moins un ingrédient valide est requis");
    }

    const invalidIngredient = newRecipe.ingredients.find(ing => 
      !ing.nom || isNaN(ing.quantite) || ing.quantite <= 0
    );

    if (invalidIngredient) {
      throw new Error(`Ingrédient invalide: ${invalidIngredient.nom || 'sans nom'}`);
    }

    const createdRecipe = addRecette(newRecipe);
    
    res.status(201).json({
      success: true,
      data: {
        ...createdRecipe,
        image: createdRecipe.image ? `${req.protocol}://${req.get('host')}${createdRecipe.image}` : null
      }
    });

  } catch (error) {
    // Nettoyage du fichier uploadé en cas d'erreur
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
    const recetteId = parseInt(req.params.id);
    deleteRecette(recetteId);
    res.json({ success: true, message: 'Recette supprimée' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===================== MOUVEMENTS ROUTES =====================

app.get('/api/mouvements', authenticate, (req, res) => {
  try {
    const data = loadData();
    const mouvements = data.data.mouvements.map(mouvement => ({
      ...mouvement,
      details: mouvement.details && mouvement.details.source ? {
        ...mouvement.details,
      } : mouvement.details
    }));
    res.json(mouvements || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Ajouter dans votre backend
app.post('/api/recettes-avec-stock', authenticate, upload.single('image'), (req, res) => {
  try {
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
      user: req.user.userId
    };

    const createdRecipe = addRecetteWithStockUpdate(newRecipe);
    res.status(201).json({
      ...createdRecipe,
      image: createdRecipe.image ? `http://localhost:3001${createdRecipe.image}` : null
    });
  } catch (error) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(400).json({ error: error.message });
  }
});


// ===================== ALERTES ROUTES =====================

app.get('/api/alertes', authenticate, (req, res) => {
  try {
    const alerts = checkStockAlerts();
    res.json(alerts || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===================== RAPPORTS ROUTES =====================

app.get('/api/rapports', authenticate, (req, res) => {
  try {
    const data = loadData();
    const rapports = {
      ventes: data.data.rapports.ventes.map(v => ({
        ...v,
      })),
      depenses: data.data.rapports.depenses.map(d => ({
        ...d,
      })),
      benefices: data.data.rapports.benefices.map(b => ({
        ...b,
      }))
    };
    res.json(rapports);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



// Staff routes (SuperAdmin)
app.get('/api/staff', authenticate, (req, res) => {
  try {
    const data = loadData();
    const currentUser = data.data.users.find(u => u.id === req.user.userId);

    if (!currentUser || currentUser.role !== 'superAdmin') {
      return res.status(403).json({ error: 'Action non autorisée' });
    }

    const staffMembers = data.data.users.filter(user => user.role === 'admin');
    res.json(staffMembers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/staff', authenticate, async (req, res) => {
  try {
    const data = loadData();
    const { email, password } = req.body;

    const currentUser = data.data.users.find(u => u.id === req.user.userId);
    if (!currentUser || currentUser.role !== 'superAdmin') {
      return res.status(403).json({ error: 'Action non autorisée' });
    }

    if (data.data.users.some(u => u.email === email)) {
      return res.status(400).json({ error: 'Cet email est déjà utilisé' });
    }

    const newAdmin = {
      id: generateId(data.data.users),
      email,
      passwordHash: await hashPassword(password),
      role: 'admin',
      createdAt: new Date().toISOString(),
      createdBy: req.user.userId
    };

    data.data.users.push(newAdmin);
    saveData(data);

    res.status(201).json({
      id: newAdmin.id,
      email: newAdmin.email,
      role: newAdmin.role
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/staff/:id', authenticate, async (req, res) => {
  try {
    const data = loadData();
    const userId = parseInt(req.params.id);
    const currentUser = data.data.users.find(u => u.id === req.user.userId);

    if (!currentUser || currentUser.role !== 'superAdmin') {
      return res.status(403).json({ error: 'Action non autorisée' });
    }

    const userToDelete = data.data.users.find(u => u.id === userId);
    if (!userToDelete) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    if (userToDelete.role === 'superAdmin') {
      return res.status(403).json({ error: 'Impossible de supprimer un superAdmin' });
    }

    data.data.users = data.data.users.filter(u => u.id !== userId);
    saveData(data);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.post('/api/verify-password', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.user.userId;

    // 1. Chargement des données
    const data = loadData();
    
    // 2. Vérification de l'utilisateur
    const user = data.data.users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    // 3. Vérification du rôle SuperAdmin
    if (user.role !== 'superAdmin') {
      return res.status(403).json({ error: 'Action réservée aux SuperAdmins' });
    }

    // 4. Comparaison des mots de passe
    const isValid = await verifyPassword(password, user.passwordHash);
    
    // 5. Réponse sécurisée
    res.json({ 
      valid: isValid,
      user: { // Ne renvoyez jamais le hash!
        id: user.id,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Erreur de vérification:', error);
    res.status(400).json({ 
      error: error.message || 'Erreur lors de la vérification'
    });
  }
});


// ===================== HISTORIQUE ROUTES =====================

app.get('/api/history', authenticate, (req, res) => {
  try {
    const data = loadData();

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
      acc[user.id] = user.email;
      return acc;
    }, {});

    const productsMap = data.data.stock.reduce((acc, product) => {
      acc[product.id] = product.nom;
      return acc;
    }, {});

    const recipesMap = data.data.recettes.reduce((acc, recipe) => {
      acc[recipe.id] = recipe.nom;
      return acc;
    }, {});

    const suppliersMap = {};
    data.data.commandes.forEach(cmd => {
      if (cmd.fournisseur && cmd.id) {
        suppliersMap[cmd.id] = cmd.fournisseur;
      }
    });

    const completeHistory = data.logs.actions.map(log => {
      const baseEntry = {
        id: log.id,
        timestamp: log.timestamp,
        date: new Date(log.timestamp).toLocaleString(),
        actionType: actionMap[log.action] || log.action,
        user: usersMap[log.user] || log.user || 'system'
      };

      switch (log.action) {
        case 'ADD_STOCK_ITEM':
          return {
            ...baseEntry,
            details: {
              productId: data.data.stock.find(p => p.nom === log.details.nom)?.id,
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
              productId: data.data.stock.find(p => p.nom === log.details.nom)?.id,
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
                stockAfter: data.data.stock.find(s => s.nom === p.nom)?.quantite
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

// ===================== INITIALISATION ROUTE =====================

app.post('/api/init', authenticate, (req, res) => {
  try {
    saveData(initDataStructure());
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint non trouvé' });
});

// Server startup
 const PORT = process.env.PORT || 10000;
  app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Backend démarré sur http://0.0.0.0:${PORT}`);

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

