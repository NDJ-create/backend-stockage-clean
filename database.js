const fs = require('fs');
const path = require('path');

// Chemins des fichiers
const filePath = path.join(__dirname, 'data/historique.json');
const LICENCE_FILE = path.join(__dirname, 'licences.json');
const LICENCE_LOG_FILE = path.join(__dirname, 'licence_logs.json');

// --------------------------------------
// STRUCTURES DE DONNÉES
// --------------------------------------

function initDataStructure() {
  return {
    meta: { 
      appName: 'gestion-stock-restaurant', 
      version: '1.0.0' 
    },
    system: { 
      lastUpdate: new Date().toISOString() 
    },
    data: {
      stock: [],
      recettes: [],
      commandes: [],
      ventes: [],
      mouvements: [],
      rapports: { 
        ventes: [], 
        depenses: [], 
        benefices: [] 
      },
      users: [],
      licences: []
    },
    logs: { 
      actions: [], 
      errors: [] 
    }
  };
}

function initLicenceStructure() {
  return {
    version: 2,
    licences: [],
    lastId: 0,
    revokedKeys: [],
    meta: {
      initializedAt: new Date().toISOString()
    }
  };
}

// --------------------------------------
// FONCTIONS PRINCIPALES
// --------------------------------------

function loadData(file = filePath) {
  try {
    // Crée le dossier si inexistant
    if (!fs.existsSync(path.dirname(file))) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
    }

    // Crée le fichier avec structure vide si inexistant
    if (!fs.existsSync(file)) {
      const data = file === LICENCE_FILE ? initLicenceStructure() : initDataStructure();
      fs.writeFileSync(file, JSON.stringify(data, null, 2));
      return data;
    }

    // Lit le fichier existant
    const content = fs.readFileSync(file, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    console.error("Erreur de chargement:", error);
    return file === LICENCE_FILE ? initLicenceStructure() : initDataStructure();
  }
}

function saveData(data, file = filePath) {
  try {
    if (!data) {
      throw new Error("Aucune donnée à sauvegarder");
    }

    // Mise à jour du timestamp pour le fichier principal
    if (file === filePath && data.system) {
      data.system.lastUpdate = new Date().toISOString();
    }

    fs.writeFileSync(file, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error("Erreur de sauvegarde:", error);
    throw error;
  }
}

function updateStockForOrder(ingredients) {
  const data = loadData();
  
  try {
    // Vérification et réduction du stock
    const updates = ingredients.map(ing => {
      const item = data.data.stock.find(i => i.id === ing.id);
      if (!item) throw new Error(`Ingrédient ${ing.id} introuvable`);
      if (item.quantite < ing.quantite) throw new Error(`Stock insuffisant pour ${item.nom}`);
      
      item.quantite -= ing.quantite;
      return {
        id: item.id,
        nom: item.nom,
        ancienneQuantite: item.quantite + ing.quantite,
        nouvelleQuantite: item.quantite
      };
    });

    // Sauvegarde unique
    saveData(data);
    return updates;
    
  } catch (error) {
    console.error("Erreur updateStockForOrder:", error);
    throw error;
  }
}

function generateId(items = []) {
  return items.length > 0 ? Math.max(...items.map(item => item.id)) + 1 : 1;
}

// --------------------------------------
// FONCTIONS SPÉCIFIQUES AUX LICENCES
// --------------------------------------

function loadLicenceData() {
  return loadData(LICENCE_FILE);
}

function saveLicenceData(data) {
  return saveData(data, LICENCE_FILE);
}

function loadLicenceLogs() {
  return loadData(LICENCE_LOG_FILE);
}

function saveLicenceLogs(data) {
  return saveData(data, LICENCE_LOG_FILE);
}

// --------------------------------------
// EXPORTS
// --------------------------------------

module.exports = {
  // Core functions
  initDataStructure,
  loadData,
  saveData,
  generateId,
  updateStockForOrder,
  // Licence functions
  loadLicenceData,
  saveLicenceData,
  loadLicenceLogs,
  saveLicenceLogs
};
