const {
  loadData,
  saveData,
  generateId,
  initDataStructure
} = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ==============================================
// CORE FUNCTIONS
// ==============================================

function logAction(action, details) {
  const data = loadData();

  if (!data.logs) {
    data.logs = { actions: [], errors: [] };
  }

  const actionMap = {
    // Stock
    'ADD_STOCK_ITEM': 'STOCK_ADD',
    'UPDATE_STOCK_ITEM': 'STOCK_UPDATE',
    'DELETE_STOCK_ITEM': 'STOCK_DELETE',

    // Commandes
    'ADD_COMMANDE': 'ORDER_ADD',
    'VALIDER_COMMANDE': 'ORDER_VALIDATE',
    'ANNULER_COMMANDE': 'ORDER_CANCEL',

    // Recettes
    'ADD_RECETTE': 'RECIPE_ADD',
    'ADD_RECETTE_WITH_STOCK_UPDATE': 'RECIPE_USE_STOCK',
    'DELETE_RECETTE': 'RECIPE_DELETE',

    // Ventes
    'ADD_VENTE': 'SALE_CREATE',
    'VALIDER_VENTE': 'SALE_COMPLETE',

    // Users
    'USER_CREATED': 'USER_CREATE',
    'USER_LICENCE_UPDATED': 'user_update'
  };

  const logEntry = {
    id: generateId(data.logs.actions),
    timestamp: new Date().toISOString(),
    action: actionMap[action] || action.toLowerCase(),
    user: details.user || 'system',
    details: {
      ...details,
      timestamp: new Date().toISOString()
    }
  };

  data.logs.actions.unshift(logEntry);
  saveData(data);

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
    process.env.SECRET_KEY || 'votre_cle_secrete_super_secrete',
    { expiresIn: '24h' }
  );
}

// ==============================================
// USER MANAGEMENT
// ==============================================

async function createUser(userData) {
  const data = loadData();

  if (data.data.users.some(u => u.email === userData.email && u.licenceKey === userData.licenceKey)) {
    throw new Error('Email déjà utilisé');
  }

  const newUser = {
    id: generateId(data.data.users),
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

  data.data.users.push(newUser);
  saveData(data);

  logAction('USER_CREATED', {
    userId: newUser.id,
    email: newUser.email,
    role: newUser.role,
    user: userData.createdBy || 'system'
  });

  return newUser;
}

async function findUserByEmail(email, licenceKey) {
  const data = loadData();
  return data.data.users.find(u => u.email === email && u.licenceKey === licenceKey);
}

async function updateUserLicence(userId, licenceKey) {
  const data = loadData();
  const user = data.data.users.find(u => u.id === userId);

  if (!user) {
    throw new Error('Utilisateur non trouvé');
  }

  user.licenceKey = licenceKey;
  saveData(data);

  logAction('USER_LICENCE_UPDATED', {
    userId: user.id,
    licenceKey,
    user: 'system'
  });

  return user;
}

// ==============================================
// STOCK MANAGEMENT
// ==============================================

function addStockItem(itemData, licenceKey) {
  const data = loadData();

  const newItem = {
    id: generateId(data.data.stock),
    nom: itemData.nom,
    quantite: parseInt(itemData.quantite) || 0,
    prixAchat: parseFloat(itemData.prixAchat) || 0,
    seuilAlerte: parseInt(itemData.seuilAlerte) || 5,
    categorie: itemData.categorie || 'autre',
    dateAjout: new Date().toISOString(),
    addedBy: itemData.user || 'system',
    licenceKey
  };

  data.data.stock.push(newItem);

  logAction('ADD_STOCK_ITEM', {
    productId: newItem.id,
    nom: newItem.nom,
    quantite: newItem.quantite,
    prixAchat: newItem.prixAchat,
    categorie: newItem.categorie,
    user: itemData.user || 'system'
  });

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

  saveData(data);
  return newItem;
}

function updateStockItem(itemData, licenceKey) {
  const data = loadData();
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
  });

  saveData(data);
  return item;
}

function deleteStockItem(itemId, userId = 'system', licenceKey) {
  const data = loadData();
  const item = data.data.stock.find(item => item.id === itemId && item.licenceKey === licenceKey);

  if (!item) {
    throw new Error("Produit non trouvé");
  }

  data.data.stock = data.data.stock.filter(item => item.id !== itemId && item.licenceKey === licenceKey);

  logAction('DELETE_STOCK_ITEM', {
    productId: item.id,
    nom: item.nom,
    derniereQuantite: item.quantite,
    user: userId
  });

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

  saveData(data);
}

function checkStockAlerts(licenceKey) {
  const data = loadData();
  return data.data.stock.filter(item => item.quantite <= (item.seuilAlerte || 5) && item.licenceKey === licenceKey);
}

// ==============================================
// ORDER MANAGEMENT
// ==============================================
function addCommande(commandeData, licenceKey) {
  const data = loadData();

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
  saveData(data);

  logAction('ADD_COMMANDE', {
    commandeId: newCommande.id,
    productName: newCommande.productName,
    produits: newCommande.produits,
    fournisseur: newCommande.fournisseur,
    montant: newCommande.montant,
    user: commandeData.user || 'system'
  });

  return newCommande;
}

function validerCommande(commandeId, userId = 'system', licenceKey) {
  const data = loadData();
  const commande = data.data.commandes.find(c => c.id === commandeId);

  if (!commande) {
    throw new Error(`Commande ${commandeId} non trouvée`);
  }

  if (commande.statut === 'validée') {
    throw new Error('Commande déjà validée');
  }

  // Log avant modification
  const produitsAvant = commande.produits.map(p => {
    const item = data.data.stock.find(s => s.nom === p.nom);
    return {
      nom: p.nom,
      stockAvant: item?.quantite || 0
    };
  });

  // Traitement
  commande.statut = 'validée';
  commande.dateValidation = new Date().toISOString();
  commande.validatedBy = userId;

  commande.produits.forEach(produit => {
    let stockItem = data.data.stock.find(item => item.nom === produit.nom);

    if (!stockItem) {
      stockItem = {
        id: generateId(data.data.stock),
        nom: produit.nom,
        quantite: 0,
        prixAchat: produit.prixUnitaire,
        seuilAlerte: 5,
        categorie: 'nouveau',
        dateAjout: new Date().toISOString(),
        addedBy: userId,
        licenceKey
      };
      data.data.stock.push(stockItem);
    }

    const ancienStock = stockItem.quantite;
    stockItem.quantite += produit.quantite;

    // Log mouvement
    data.data.mouvements.push({
      id: generateId(data.data.mouvements),
      productId: stockItem.id,
      nom: stockItem.nom,
      type: 'réception_commande',
      quantite: produit.quantite,
      date: new Date().toISOString(),
      details: {
        commandeId: commande.id,
        fournisseur: commande.fournisseur,
        prixUnitaire: produit.prixUnitaire,
        stockAvant: ancienStock,
        user: userId
      },
      licenceKey
    });
  });

  // Log complet
  logAction('VALIDER_COMMANDE', {
    commandeId: commande.id,
    fournisseur: commande.fournisseur,
    produits: commande.produits.map(p => ({
      nom: p.nom,
      quantite: p.quantite,
      prixUnitaire: p.prixUnitaire,
      montant: p.quantite * p.prixUnitaire,
      stockAfter: data.data.stock.find(s => s.nom === p.nom)?.quantite || 0
    })),
    montantTotal: commande.montant,
    user: userId
  });

  // Rapport financier
  data.data.rapports.depenses.push({
    id: generateId(data.data.rapports.depenses),
    commandeId: commande.id,
    montant: commande.montant,
    date: new Date().toISOString(),
    fournisseur: commande.fournisseur,
    validatedBy: userId,
    licenceKey
  });

  saveData(data);
  return commande;
}

function annulerCommande(commandeId, userId = 'system', licenceKey) {
  const data = loadData();
  const commande = data.data.commandes.find(c => c.id === commandeId && c.licenceKey === licenceKey);

  if (!commande) {
    throw new Error(`Commande ${commandeId} non trouvée`);
  }

  commande.statut = 'annulée';
  commande.annulationDate = new Date().toISOString();
  commande.annulatedBy = userId;

  saveData(data);

  logAction('ANNULER_COMMANDE', {
    commandeId: commande.id,
    raison: 'annulation manuelle',
    user: userId
  });

  return commande;
}

// ==============================================
// RECIPE MANAGEMENT
// ==============================================

function addRecette(recetteData, licenceKey) {
  const data = loadData();

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
  saveData(data);

  logAction('ADD_RECETTE', {
    recetteId: newRecette.id,
    nom: newRecette.nom,
    prix: newRecette.prix,
    ingredients: newRecette.ingredients,
    user: recetteData.user || 'system'
  });

  return newRecette;
}

function addRecetteWithStockUpdate(recetteData, licenceKey) {
  const data = loadData();

  // Vérification stock
  for (const ingredient of recetteData.ingredients) {
    const stockItem = data.data.stock.find(item => item.id === ingredient.id && item.licenceKey === licenceKey);
    if (!stockItem || stockItem.quantite < ingredient.quantite) {
      throw new Error(`Ingrédient "${stockItem?.nom || ingredient.nom}" en stock insuffisant`);
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

  // Mise à jour stock et mouvements
  for (const ingredient of recetteData.ingredients) {
    const stockItem = data.data.stock.find(item => item.id === ingredient.id && item.licenceKey === licenceKey);
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
  saveData(data);

  logAction('ADD_RECETTE_WITH_STOCK_UPDATE', {
    recetteId: newRecette.id,
    nom: newRecette.nom,
    ingredients: newRecette.ingredients.map(i => ({
      id: i.id,
      nom: data.data.stock.find(s => s.id === i.id && s.licenceKey === licenceKey)?.nom || i.nom,
      quantite: i.quantite
    })),
    user: recetteData.user || 'system'
  });

  return newRecette;
}

function deleteRecette(recetteId, userId = 'system', licenceKey) {
  const data = loadData();
  const recetteIndex = data.data.recettes.findIndex(r => r.id === recetteId && r.licenceKey === licenceKey);

  if (recetteIndex === -1) {
    throw new Error("Recette non trouvée");
  }

  const recette = data.data.recettes[recetteIndex];
  data.data.recettes.splice(recetteIndex, 1);
  saveData(data);

  logAction('DELETE_RECETTE', {
    recetteId: recette.id,
    nom: recette.nom,
    user: userId
  });
}

// ==============================================
// SALES MANAGEMENT
// ==============================================

function addVente(venteData, licenceKey) {
  const data = loadData();
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
  saveData(data);

  logAction('ADD_VENTE', {
    venteId: newVente.id,
    recetteId: newVente.recetteId,
    recetteNom: recette.nom,
    quantite: newVente.quantite,
    prixTotal: newVente.prixTotal,
    client: newVente.client,
    user: venteData.user || 'system'
  });

  return newVente;
}

function validerVente(venteId, userId = 'system', licenceKey) {
  const data = loadData();
  const vente = data.data.ventes.find(v => v.id === venteId && v.licenceKey === licenceKey);
  const recette = data.data.recettes.find(r => r.id === vente.recetteId && r.licenceKey === licenceKey);

  if (!vente || !recette) {
    throw new Error("Vente ou recette non trouvée");
  }

  if (vente.statut === 'validée') {
    throw new Error("Vente déjà validée");
  }

  // Vérification stock
  for (const ingredient of recette.ingredients) {
    const stockItem = data.data.stock.find(item => item.id === ingredient.id && item.licenceKey === licenceKey);
    if (!stockItem || stockItem.quantite < (ingredient.quantite * vente.quantite)) {
      throw new Error(`Stock insuffisant pour ${stockItem?.nom || ingredient.nom}`);
    }
  }

  // Calcul coûts
  let coutTotal = 0;
  recette.ingredients.forEach(ingredient => {
    const stockItem = data.data.stock.find(item => item.id === ingredient.id && item.licenceKey === licenceKey);
    coutTotal += stockItem.prixAchat * ingredient.quantite;
  });

  const beneficeTotal = vente.prixTotal - coutTotal;

  // Mise à jour stock
  recette.ingredients.forEach(ingredient => {
    const stockItem = data.data.stock.find(item => item.id === ingredient.id && item.licenceKey === licenceKey);
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

  // Mise à jour vente
  vente.statut = 'validée';
  vente.dateValidation = new Date().toISOString();
  vente.coutTotal = coutTotal;
  vente.benefice = beneficeTotal;
  vente.validatedBy = userId;

  // Rapports financiers
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

  saveData(data);

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
  });

  return {
    vente: vente,
    benefice: beneficeTotal
  };
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
  checkStockAlerts,

  // Commandes
  addCommande,
  validerCommande,
  annulerCommande,

  // Recettes
  addRecette,
  addRecetteWithStockUpdate,
  deleteRecette,

  // Ventes
  addVente,
  validerVente
};
