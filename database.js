const fs = require('fs');
const path = require('path');

// Chemins des fichiers
const DATA_FILES = {
  main: path.join(__dirname, 'data/main.json'),
  users: path.join(__dirname, 'data/users.json'),
  licences: path.join(__dirname, 'data/licences.json'),
  licenceLog: path.join(__dirname, 'data/licence_logs.json')
};

// Structure de données initiale pour main.json
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
      staff: [],     
      mouvements: [],
      rapports: {
        ventes: [],
        depenses: [],
        benefices: []
      }
    },
    logs: {
      actions: [],
      errors: []
    }
  };
}

// Structure de données initiale pour licences.json
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

// Charger les données
function loadData(fileKey) {
  try {
    // Créer le dossier si inexistant
    if (!fs.existsSync(path.dirname(DATA_FILES[fileKey]))) {
      fs.mkdirSync(path.dirname(DATA_FILES[fileKey]), { recursive: true });
    }

    // Créer le fichier avec structure initiale si inexistant
    if (!fs.existsSync(DATA_FILES[fileKey])) {
      let initialData;
      switch(fileKey) {
        case 'licences':
          initialData = initLicenceStructure();
          break;
        case 'main':
          initialData = initDataStructure();
          break;
        case 'users':
          initialData = { users: [] };
          break;
        case 'licenceLog':
          initialData = { logs: [] };
          break;
        default:
          initialData = {};
      }
      fs.writeFileSync(DATA_FILES[fileKey], JSON.stringify(initialData, null, 2));
      return initialData;
    }

    // Lire le fichier existant
    const content = fs.readFileSync(DATA_FILES[fileKey], 'utf8');
    const parsed = JSON.parse(content);

    // Si c'est users.json et que c'est un tableau, retourner le tableau
    if (fileKey === 'users' && Array.isArray(parsed)) {
      return parsed;
    }

    return parsed;

  } catch (error) {
    console.error(`Erreur loadData(${fileKey}):`, error);
    return fileKey === 'licences' ? initLicenceStructure() : {};
  }
}

function saveData(fileKey, data) {
  try {
    if (!data) throw new Error("Données manquantes");
    fs.writeFileSync(DATA_FILES[fileKey], JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`Erreur saveData(${fileKey}):`, error);
    throw error;
  }
}

// Générer un ID
function generateId(items = []) {
  try {
    const ids = items
      .map(item => parseInt(item.id))
      .filter(id => !isNaN(id) && id >= 0);
    return ids.length > 0 ? Math.max(...ids) + 1 : Date.now();
  } catch {
    return Date.now();
  }
}
// Fonction pour mettre à jour le stock pour une commande
function updateStockForOrder(ingredients, licenceKey) {
  const data = loadData('main');

  try {
    const updates = ingredients.map(ing => {
      const item = data.data.stock.find(i => i.id === ing.id && i.licenceKey === licenceKey);
      if (!item) throw new Error(`Ingrédient ${ing.id} non trouvé`);
      if (item.quantite < ing.quantite) throw new Error(`Stock insuffisant pour ${item.nom}`);

      item.quantite -= ing.quantite;

      // Ajout mouvement historique
      data.data.mouvements.push({
        id: generateId(data.data.mouvements),
        produitId: item.id,
        type: 'sortie',
        quantite: ing.quantite,
        date: new Date().toISOString(),
        licenceKey: item.licenceKey
      });

      return {
        id: item.id,
        nom: item.nom,
        ancienneQuantite: item.quantite + ing.quantite,
        nouvelleQuantite: item.quantite
      };
    });

    saveData('main', data);
    return updates;

  } catch (error) {
    console.error("Erreur updateStockForOrder:", error);
    throw error;
  }
}

// Fonctions pour gérer les licences
function loadLicenceData() {
  return loadData('licences');
}

function saveLicenceData(data) {
  return saveData('licences', data);
}

function loadLicenceLogs() {
  return loadData('licenceLog');
}

function saveLicenceLogs(data) {
  return saveData('licenceLog', data);
}

// Exports
module.exports = {
  DATA_FILES,
  initDataStructure,
  loadData,
  saveData,
  generateId,
  updateStockForOrder,
  loadLicenceData,
  saveLicenceData,
  loadLicenceLogs,
  saveLicenceLogs
};
