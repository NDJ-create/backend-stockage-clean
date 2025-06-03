const {
  loadData,
  saveData,
  generateId,
  initDataStructure
} = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.SECRET_KEY;
// ==============================================
// CORE FUNCTIONS
// ==============================================
function logAction(action, details, licenceKey) {
  const data = loadData('main');

  if (!data.logs) {
    data.logs = { actions: [], errors: [] };
  }

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

  // Vérifie que action est une chaîne de caractères
  if (typeof action !== 'string') {
    throw new Error('Action doit être une chaîne de caractères');
  }

  const logEntry = {
    id: generateId(data.logs.actions),
    timestamp: new Date().toISOString(),
    action: actionMap[action] || action.toLowerCase(),
    user: details.user || 'system',
    licenceKey: licenceKey,
    details: {
      ...details,
      timestamp: new Date().toISOString()
    }
  };

  data.logs.actions.unshift(logEntry);
  saveData('main', data);

  return logEntry;
}


// ==============================================
// AUTHENTIFICATION
// ==============================================

async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function generateAuthToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      role: user.role,
      email: user.email,
      licenceKey: user.licenceKey || null
    },
    SECRET_KEY,
    { expiresIn: '24h' }
  );
}
// ==============================================
// USER MANAGEMENT
// ==============================================

async function createUser(userData, licenceKey) {
  const data = loadData('users');

  if (data.users.some(u => u.email === userData.email)) {
    throw new Error('Email déjà utilisé');
  }

  const newUser = {
    id: generateId(data.users),
    email: userData.email,
    passwordHash: await hashPassword(userData.password),
    role: userData.role || 'user',
    licenceKey: userData.licenceKey || null,
    createdAt: new Date().toISOString(),
    createdBy: userData.createdBy || 'system'
  };

  if (userData.secretQuestion && userData.secretAnswer) {
    newUser.secretQuestion = userData.secretQuestion;
    newUser.secretAnswer = userData.secretAnswer;
  }

  data.users.push(newUser);
  saveData('users', data);

  logAction('USER_CREATED', {
    userId: newUser.id,
    email: newUser.email,
    role: newUser.role,
    user: userData.createdBy || 'system'
  }, licenceKey);

  return newUser;
}

async function findUserByEmail(email, licenceKey) {
  const data = loadData('users'); // charge users.json

  // Si users.json est un tableau directement (comme dans ton cas)
  const users = Array.isArray(data) ? data : (data.users || []);

  return users.find(u => u.email === email && u.licenceKey === licenceKey);
}

async function updateUserLicence(userId, licenceKey) {
  const data = loadData('users');
  const user = data.users.find(u => u.id === userId);

  if (!user) {
    throw new Error('Utilisateur non trouvé');
  }

  user.licenceKey = licenceKey;
  saveData('users', data);

  logAction('USER_LICENCE_UPDATED', {
    userId: user.id,
    licenceKey,
    user: 'system'
  }, licenceKey);

  return user;
}

// ==============================================
// STOCK MANAGEMENT
// ==============================================
function addStockItem(itemData, licenceKey, data) {
  const newItem = {
    id: generateId(data.data.stock),
    nom: itemData.nom,
    quantite: parseFloat(itemData.quantite) || 0,
    prixAchat: parseFloat(itemData.prixAchat) || 0,
    unite: itemData.unite || 'unité', // ✅ unité ajoutée ici
    seuilAlerte: parseInt(itemData.seuilAlerte) || 5,
    categorie: itemData.categorie || 'autre',
    dateAjout: new Date().toISOString(),
    addedBy: itemData.user || 'system',
    licenceKey
  };

  // Ajouter dans le stock
  data.data.stock.push(newItem);

  // Ajouter dans les mouvements
  data.data.mouvements.push({
    id: generateId(data.data.mouvements),
    productId: newItem.id,
    type: 'ajout',
    quantite: newItem.quantite,
    date: new Date().toISOString(),
    details: {
      source: 'ajout_manuel',
      prixUnitaire: newItem.prixAchat,
      user: itemData.user || 'system'
    },
    licenceKey
  });

  // Ajouter dans l'historique (logs.actions)
  data.logs.actions.push({
    id: generateId(data.logs.actions),
    timestamp: new Date().toISOString(),
    action: 'ADD_STOCK_ITEM',
    user: itemData.user || 'system',
    licenceKey,
    details: {
      nom: newItem.nom,
      quantite: newItem.quantite,
      prixAchat: newItem.prixAchat,
      unite: newItem.unite, // ✅ ajouté aussi dans les détails de logs
      categorie: newItem.categorie
    }
  });

  return newItem;
}

function updateStockItem(itemData, licenceKey) {
  const data = loadData('main');
  const item = data.data.stock.find(i => i.id === itemData.id && i.licenceKey === licenceKey);

  if (!item) {
    throw new Error("Produit non trouvé");
  }

  const ancienneQuantite = item.quantite;
  const ancienPrix = item.prixAchat;

  Object.assign(item, {
    ...itemData,
    quantite: parseInt(itemData.quantite) || item.quantite,
    prixAchat: parseFloat(itemData.prixAchat) || item.prixAchat,
    licenceKey
  });

  if (ancienneQuantite !== item.quantite || ancienPrix !== item.prixAchat) {
    data.data.mouvements.push({
      id: generateId(data.data.mouvements),
      productId: item.id,
      type: 'modification',
      quantite: item.quantite - ancienneQuantite,
      date: new Date().toISOString(),
      details: {
        source: 'modification_manuelle',
        ancienneQuantite,
        nouvelleQuantite: item.quantite,
        ancienPrix,
        nouveauPrix: item.prixAchat,
        user: itemData.user || 'system'
      },
      licenceKey
    });
  }

  logAction('UPDATE_STOCK_ITEM', {
    productId: item.id,
    nom: item.nom,
    ancienneQuantite,
    nouvelleQuantite: item.quantite,
    ancienPrix,
    nouveauPrix: item.prixAchat,
    user: itemData.user || 'system'
  }, licenceKey);

  saveData('main', data);
  return item;
}

function deleteStockItem(itemId, userId = 'system', licenceKey) {
  const data = loadData('main');
  const item = data.data.stock.find(item => item.id === itemId && item.licenceKey === licenceKey);

  if (!item) {
    throw new Error("Produit non trouvé");
  }

  data.data.stock = data.data.stock.filter(item => item.id !== itemId || item.licenceKey !== licenceKey);

  logAction('DELETE_STOCK_ITEM', {
    productId: item.id,
    nom: item.nom,
    derniereQuantite: item.quantite,
    user: userId
  }, licenceKey);

  data.data.mouvements.push({
    id: generateId(data.data.mouvements),
    type: 'suppression',
    productId: itemId,
    date: new Date().toISOString(),
    details: {
      nom: item.nom,
      derniereQuantite: item.quantite,
      user: userId
    },
    licenceKey
  });

  saveData('main', data);
}

function checkStockAlerts(licenceKey) {
  const data = loadData('main');
  return data.data.stock.filter(item => item.quantite <= item.seuilAlerte && item.licenceKey === licenceKey);
}

// ==============================================
// ORDER MANAGEMENT
// ==============================================

function addCommande(commandeData, licenceKey) {
  const data = loadData('main');

  const newCommande = {
    id: commandeData.id || generateId(data.data.commandes),
    fournisseur: commandeData.fournisseur,
    fournisseurEmail: commandeData.fournisseurEmail,
    productName: commandeData.productName || commandeData.nomProduit,
    produits: commandeData.produits || [{
      nom: commandeData.nomProduit,
      quantite: parseInt(commandeData.quantite) || 1,
      prixUnitaire: parseFloat(commandeData.prix) || 0
    }],
    montant: parseFloat(commandeData.montant) ||
             (parseFloat(commandeData.prix) * (parseInt(commandeData.quantite) || 1)),
    statut: commandeData.statut || 'en_attente',
    date: commandeData.date || new Date().toISOString(),
    deliveryDate: commandeData.deliveryDate || null,
    user: commandeData.user || 'system',
    licenceKey
  };

  data.data.commandes.push(newCommande);
  saveData('main', data);

  logAction('ADD_COMMANDE', {
    commandeId: newCommande.id,
    productName: newCommande.productName,
    produits: newCommande.produits,
    fournisseur: newCommande.fournisseur,
    montant: newCommande.montant,
    user: commandeData.user || 'system'
  }, licenceKey);

  return newCommande;
}


function validerCommande(commandeId, userId = 'system', licenceKey) {
  const data = loadData('main');

  // Sécurité structure
  if (!data.data.stock) data.data.stock = [];
  if (!data.data.mouvements) data.data.mouvements = [];
  if (!data.data.rapports) data.data.rapports = {};
  if (!data.data.rapports.depenses) data.data.rapports.depenses = [];
  if (!data.logs) data.logs = {};
  if (!data.logs.actions) data.logs.actions = [];

  const commande = data.data.commandes.find(
    c => c.id === commandeId && c.licenceKey === licenceKey
  );
  if (!commande) {
    throw new Error(`Commande ${commandeId} non trouvée ou non autorisée`);
  }

  if (commande.statut === 'validée') {
    throw new Error('Commande déjà validée');
  }

  const now = new Date().toISOString();
  commande.statut = 'validée';
  commande.dateValidation = now;
  commande.validatedBy = userId;

  const produitsAjoutes = [];

  commande.produits.forEach(produit => {
    let stockItem = data.data.stock.find(
      item => item.nom === produit.nom && item.licenceKey === licenceKey
    );

    if (!stockItem) {
      stockItem = {
        id: generateId(data.data.stock),
        nom: produit.nom,
        quantite: 0,
        prixAchat: produit.prixUnitaire,
        seuilAlerte: 5,
        categorie: 'nouveau',
        unite: produit.unite,
        dateAjout: now,
        addedBy: userId,
        licenceKey: licenceKey
      };
      data.data.stock.push(stockItem);
    }

    const ancienStock = stockItem.quantite;
    stockItem.quantite += produit.quantite;

    produitsAjoutes.push({
      nom: produit.nom,
      quantite: produit.quantite,
      prixUnitaire: produit.prixUnitaire,
      stockAvant: ancienStock,
      stockApres: stockItem.quantite,
      unite: produit.unite
    });

    data.data.mouvements.push({
      id: generateId(data.data.mouvements),
      productId: stockItem.id,
      nom: stockItem.nom,
      type: 'réception_commande',
      quantite: produit.quantite,
      date: now,
      details: {
        commandeId: commande.id,
        fournisseur: commande.fournisseur,
        prixUnitaire: produit.prixUnitaire,
        stockAvant: ancienStock
      }
    });
  });

  data.data.rapports.depenses.push({
    id: generateId(data.data.rapports.depenses),
    commandeId: commande.id,
    montant: commande.montant,
    date: now,
    fournisseur: commande.fournisseur,
    validatedBy: userId,
    licenceKey: licenceKey
  });

  // Import dynamique pour éviter la dépendance circulaire
  const { getUserInfo } = require('./helpers');
  const userInfo = getUserInfo(userId, licenceKey);

  // 📜 Log de l'action
  data.logs.actions.push({
    id: generateId(data.logs.actions),
    timestamp: now,
    date: now,
    licenceKey,
    type: 'ORDER_VALIDATE',
    action: `Commande ${commande.id} validée : ${produitsAjoutes.map(p => `${p.quantite} ${p.unite} de ${p.nom} à ${p.prixUnitaire}€/u`).join(', ')}`,
    user: userInfo
      ? { id: userInfo.id, role: userInfo.role }
      : { id: userId, role: 'inconnu' }
  });

  saveData('main', data);

  return commande;
}

function annulerCommande(commandeId, userId = 'system', licenceKey) {
  const data = loadData('main');
  const commande = data.data.commandes.find(c => c.id === commandeId && c.licenceKey === licenceKey);

  if (!commande) {
    throw new Error(`Commande ${commandeId} non trouvée ou non autorisée`);
  }

  commande.statut = 'annulée';
  commande.annulationDate = new Date().toISOString();
  commande.annulatedBy = userId;

  saveData('main', data);

  logAction('ANNULER_COMMANDE', {
    commandeId: commande.id,
    raison: 'annulation manuelle',
    user: userId
  }, licenceKey);
}

// ==============================================
// RECIPE MANAGEMENT
// ==============================================

function addRecette(recetteData, licenceKey) {
  const data = loadData('main');

  const newRecette = {
    id: generateId(data.data.recettes),
    nom: recetteData.nom,
    ingredients: recetteData.ingredients,
    image: recetteData.image || "",
    prix: parseFloat(recetteData.prix) || 0,
    categorie: recetteData.categorie || 'autre',
    dateCreation: new Date().toISOString(),
    createdBy: recetteData.user || 'system',
    licenceKey
  };

  data.data.recettes.push(newRecette);
  saveData('main', data);

  logAction('ADD_RECETTE', {
    recetteId: newRecette.id,
    nom: newRecette.nom,
    prix: newRecette.prix,
    ingredients: newRecette.ingredients,
    user: recetteData.user || 'system'
  }, licenceKey);

  return newRecette;
}

function addRecetteWithStockUpdate(recetteData, licenceKey) {
  const data = loadData('main');

  for (const ingredient of recetteData.ingredients) {
    const stockItem = data.data.stock.find(item => item.nom === ingredient.nom && item.licenceKey === licenceKey);
    if (!stockItem || stockItem.quantite < ingredient.quantite) {
      throw new Error(`Ingrédient "${stockItem?.nom || ingredient.nom}" insuffisant en stock`);
    }
  }

  const newRecette = {
    id: generateId(data.data.recettes),
    nom: recetteData.nom,
    ingredients: recetteData.ingredients,
    image: recetteData.image || "",
    prix: parseFloat(recetteData.prix) || 0,
    categorie: recetteData.categorie || 'autre',
    dateCreation: new Date().toISOString(),
    createdBy: recetteData.user || 'system',
    licenceKey
  };

  for (const ingredient of recetteData.ingredients) {
    const stockItem = data.data.stock.find(item => item.nom === ingredient.nom && item.licenceKey === licenceKey);
    const ancienStock = stockItem.quantite;
    stockItem.quantite -= ingredient.quantite;

    data.data.mouvements.push({
      id: generateId(data.data.mouvements),
      productId: stockItem.id,
      nom: stockItem.nom,
      type: 'utilisation_recette',
      quantite: -ingredient.quantite,
      date: new Date().toISOString(),
      details: {
        recetteId: newRecette.id,
        recetteNom: newRecette.nom,
        stockAvant: ancienStock,
        user: recetteData.user || 'system'
      },
      licenceKey
    });
  }

  data.data.recettes.push(newRecette);
  saveData('main', data);

  logAction('ADD_RECETTE_WITH_STOCK_UPDATE', {
    recetteId: newRecette.id,
    nom: newRecette.nom,
    ingredients: newRecette.ingredients.map(i => {
      const s = data.data.stock.find(stock => stock.nom === i.nom && stock.licenceKey === licenceKey);
      return {
        id: i.id,
        nom: s?.nom || 'Inconnu',
        quantite: i.quantite
      };
    }),
    user: recetteData.user || 'system'
  }, licenceKey);

  return newRecette;
}

function deleteRecette(recetteId, userId = 'system', licenceKey) {
  const data = loadData('main');
  const recetteIndex = data.data.recettes.findIndex(r => r.id === recetteId && r.licenceKey === licenceKey);

  if (recetteIndex === -1) {
    throw new Error("Recette non trouvée");
  }

  const recette = data.data.recettes[recetteIndex];
  data.data.recettes.splice(recetteIndex, 1);
  saveData('main', data);

  logAction('DELETE_RECETTE', {
    recetteId: recette.id,
    nom: recette.nom,
    user: userId
  }, licenceKey);
}

// ==============================================
// SALES MANAGEMENT
// ==============================================

function addVente(venteData, licenceKey) {
  const data = loadData('main');
  const recette = data.data.recettes.find(r => r.id === venteData.recetteId && r.licenceKey === licenceKey);

  if (!recette) {
    throw new Error("Recette non trouvée");
  }

  const newVente = {
    id: generateId(data.data.ventes),
    recetteId: venteData.recetteId,
    recetteNom: recette.nom,
    quantite: parseInt(venteData.quantite) || 1,
    prixTotal: recette.prix * (parseInt(venteData.quantite) || 1),
    date: new Date().toISOString(),
    statut: 'en_attente',
    client: venteData.client || 'anonyme',
    user: venteData.user || 'system',
    licenceKey
  };

  data.data.ventes.push(newVente);
  saveData('main', data);

  logAction('ADD_VENTE', {
    venteId: newVente.id,
    recetteId: newVente.recetteId,
    recetteNom: recette.nom,
    quantite: newVente.quantite,
    prixTotal: newVente.prixTotal,
    client: newVente.client,
    user: venteData.user || 'system'
  }, licenceKey);

  return newVente;
}

function validerVente(venteId, userId = 'system', licenceKey) {
  const data = loadData('main');
  const vente = data.data.ventes.find(v => v.id === venteId && v.licenceKey === licenceKey);
  const recette = data.data.recettes.find(r => r.id === vente.recetteId && r.licenceKey === licenceKey);

  if (!vente || !recette) {
    throw new Error("Vente ou recette non trouvée");
  }

  if (vente.statut === 'validée') {
    throw new Error("Vente déjà validée");
  }

  for (const ingredient of recette.ingredients) {
    const stockItem = data.data.stock.find(item => item.nom === ingredient.nom && item.licenceKey === licenceKey);
    if (!stockItem || stockItem.quantite < (ingredient.quantite * vente.quantite)) {
      throw new Error(`Stock insuffisant pour ${stockItem?.nom || ingredient.nom}`);
    }
  }

  let coutTotal = 0;
  recette.ingredients.forEach(ingredient => {
    const stockItem = data.data.stock.find(item => item.nom === ingredient.nom && item.licenceKey === licenceKey);
    coutTotal += stockItem.prixAchat * ingredient.quantite;
  });

  const beneficeTotal = vente.prixTotal - coutTotal;

  recette.ingredients.forEach(ingredient => {
    const stockItem = data.data.stock.find(item => item.nom === ingredient.nom && item.licenceKey === licenceKey);
    const ancienStock = stockItem.quantite;
    stockItem.quantite -= ingredient.quantite * vente.quantite;

    data.data.mouvements.push({
      id: generateId(data.data.mouvements),
      productId: ingredient.id,
      nom: stockItem.nom,
      type: 'vente',
      quantite: -(ingredient.quantite * vente.quantite),
      date: new Date().toISOString(),
      details: {
        venteId: vente.id,
        recetteId: recette.id,
        recetteNom: recette.nom,
        prixAchat: stockItem.prixAchat,
        stockAvant: ancienStock,
        user: userId
      },
      licenceKey
    });
  });

  vente.statut = 'validée';
  vente.dateValidation = new Date().toISOString();
  vente.coutTotal = coutTotal;
  vente.benefice = beneficeTotal;
  vente.validatedBy = userId;

  data.data.rapports.ventes.push({
    id: generateId(data.data.rapports.ventes),
    venteId: vente.id,
    recetteId: recette.id,
    recetteNom: recette.nom,
    montant: vente.prixTotal,
    date: new Date().toISOString(),
    validatedBy: userId,
    licenceKey
  });

  data.data.rapports.benefices.push({
    id: generateId(data.data.rapports.benefices),
    venteId: vente.id,
    recetteId: recette.id,
    montant: beneficeTotal,
    date: new Date().toISOString(),
    validatedBy: userId,
    licenceKey
  });

  saveData('main', data);

  logAction('VALIDER_VENTE', {
    venteId: vente.id,
    recetteId: recette.id,
    recetteNom: recette.nom,
    quantite: vente.quantite,
    prixTotal: vente.prixTotal,
    coutTotal,
    benefice: beneficeTotal,
    client: vente.client,
    user: userId
  }, licenceKey);

  return {
    vente: vente,
    benefice: beneficeTotal
  };
}


// Utilisez toujours 'main' comme fileKey
function addStaffMember(staffData, licenceKey) {
  const data = loadData('main');

  if (!data.data.staff) data.data.staff = [];

  const newStaff = {
    id: generateId(data.data.staff),
    ...staffData,
    licenceKey, // Assurez-vous que la clé de licence est associée au membre du personnel
    createdAt: new Date().toISOString()
  };

  data.data.staff.push(newStaff);
  saveData('main', data);
  return newStaff;
}

function getStaffMembers(licenceKey) {
  const data = loadData('main');
  return (data.data.staff || []).filter(staff => staff.licenceKey === licenceKey);
}

function removeStaffMember(staffId, licenceKey) {
  const data = loadData('main');

  if (!data.data.staff) data.data.staff = [];

  data.data.staff = data.data.staff.filter(member => !(member.id === staffId && member.licenceKey === licenceKey));

  saveData('main', data);
}

function getUserById(userId, licenceKey) {
  const users = loadData('users');
  return users.users.find(user => user.id === userId && user.licenceKey === licenceKey);
}


function getStockAlerts(licenceKey) {
  const data = loadData('main');

  const stockItems = (data.data.stock || []).filter(item => item.licenceKey === licenceKey);

  const alertes = stockItems
    .filter(item => item.quantite <= item.seuilAlerte) // ✅ changement ici
    .map(item => ({
      id: item.id,
      nom: item.nom,
      quantite: item.quantite,
      seuilAlerte: item.seuilAlerte,
      message: "Quantité égale ou en dessous du seuil d'alerte"
    }));

  return alertes;
}
// ==============================================
// EXPORTS
// ==============================================

module.exports = {
  // Core
  loadData,
  saveData,
  generateId,
  initDataStructure,
  logAction,

  // Auth
  hashPassword,
  verifyPassword,
  generateAuthToken,
  createUser,
  findUserByEmail,
  updateUserLicence,
  // Stock
  addStockItem,
  updateStockItem,
  deleteStockItem,
  getStockAlerts,
  checkStockAlerts,

  // Commandes
  addCommande,
  validerCommande,
  annulerCommande,
  // Recettes
  addRecette,
  addRecetteWithStockUpdate,
  deleteRecette,
  
  addStaffMember,
  removeStaffMember,
  getStaffMembers,
  getUserById,  
  // Ventes
  addVente,
  validerVente
};

