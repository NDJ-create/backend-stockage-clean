const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { LICENCE_SETTINGS, BASE_URL } = require('./config');

// Chemins des fichiers
const DATA_DIR = path.join(__dirname, 'data');
const LICENCE_FILE = path.join(DATA_DIR, 'licences.json');
const LOGS_FILE = path.join(DATA_DIR, 'licence_logs.json');

// Assure que le dossier data existe
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/* ==================== */
/*  FONCTIONS UTILES    */
/* ==================== */

function generateId(existingItems = []) {
  return existingItems.length > 0 ? Math.max(...existingItems.map(i => i.id)) + 1 : 1;
}

function loadData(filePath, defaultValue = null) {
  try {
    if (!fs.existsSync(filePath)) return defaultValue;
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return data !== null ? data : defaultValue;
  } catch (error) {
    console.error(`Erreur lecture ${filePath}:`, error);
    return defaultValue;
  }
}

function saveData(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`Erreur écriture ${filePath}:`, error);
    return false;
  }
}

/* ==================== */
/*  GESTION DES LICENCES */
/* ==================== */

function loadLicenceData() {
  const defaultData = {
    version: 1,
    licences: [],
    lastId: 0,
    revokedKeys: []
  };
  return loadData(LICENCE_FILE, defaultData);
}

function saveLicenceData(data) {
  return saveData(LICENCE_FILE, data);
}

function loadLicenceLogs() {
  const logs = loadData(LOGS_FILE, []);
  return Array.isArray(logs) ? logs : [];
}

function saveLicenceLogs(logs) {
  return saveData(LOGS_FILE, logs);
}

function generateSecureKey(id) {
  return `LIC-${id}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

function logLicenceAction(action, metadata = {}) {
  const logs = loadLicenceLogs();
  logs.push({
    id: generateId(logs),
    timestamp: new Date().toISOString(),
    action,
    ...metadata
  });
  saveLicenceLogs(logs);
}

/* ==================== */
/*  FONCTIONS PRINCIPALES */
/* ==================== */

function initLicenceSystem() {
  const defaultData = {
    version: 1,
    licences: [],
    lastId: 0,
    revokedKeys: []
  };

  if (!saveLicenceData(defaultData)) {
    throw new Error('Échec initialisation système de licences');
  }

  saveLicenceLogs([]);
  return true;
}

function generateLicence(clientInfo = {}, creatorId = 'system', durationType = '1y') {
  if (!LICENCE_SETTINGS.durations.hasOwnProperty(durationType)) {
    const validDurations = Object.keys(LICENCE_SETTINGS.durations);
    const error = new Error(`Type de durée invalide (${durationType}). Types valides: ${validDurations.join(', ')}`);
    logLicenceAction('GENERATE_ERROR', {
      error: error.message,
      receivedDuration: durationType,
      validDurations
    });
    throw error;
  }

  let data = loadLicenceData();
  const licenceId = data.lastId + 1;
  const key = generateSecureKey(licenceId);
  const durationDays = LICENCE_SETTINGS.durations[durationType];

  const expiresAt = durationDays
    ? new Date(Date.now() + durationDays * 86400000).toISOString()
    : null;

  const newLicence = {
    id: licenceId,
    key,
    clientInfo,
    createdAt: new Date().toISOString(),
    expiresAt,
    isActive: true,
    used: false,
    usedAt: null,
    usedBy: null,
    createdBy: creatorId,
    durationType,
    revoked: false,
    revokedAt: null,
    revokedBy: null,
    revokedReason: null
  };

  data.licences.push(newLicence);
  data.lastId = licenceId;

  if (!saveLicenceData(data)) {
    logLicenceAction('GENERATE_ERROR', {
      error: 'Échec sauvegarde licence',
      licenceId,
      durationType
    });
    throw new Error('Échec de sauvegarde de la licence');
  }

  logLicenceAction('GENERATE', {
    licenceId,
    durationType,
    expiresAt,
    client: clientInfo.name || 'N/A',
    key
  });

  return {
    ...newLicence,
    activationUrl: `${BASE_URL}/activate?key=${key}`,
    durationDays,
    durationType
  };
}


function validateLicence(key) {
  console.log("\n=== DEBUG VALIDATION START ===");
  console.log("Clé reçue:", key);

  try {
    // 1. Chargement des données
    const data = loadLicenceData();
    const licence = data.licences.find(l => l.key === key);

    if (!licence) {
      console.log("Licence NON trouvée");
      return { 
        valid: false, 
        reason: 'invalid_key',
        key
      };
    }

    // 2. Vérification de la révocation (prioritaire)
    if (licence.revoked) {
      console.log("=== LICENCE RÉVOQUÉE ===");
      return {
        valid: false,
        isMaster: false,
        revoked: true,
        revokedAt: licence.revokedAt,
        revokedReason: licence.revokedReason,
        key,
        licence: {
          ...licence,
          isFirstUse: !licence.used,
          daysRemaining: licence.expiresAt ?
            Math.ceil((new Date(licence.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)) :
            null,
          isActive: false // Forcé à false si révoquée
        }
      };
    }

    // 3. Vérification de l'expiration et de l'état actif
    const isExpired = licence.expiresAt && new Date(licence.expiresAt) < new Date();
    const isMaster = licence.isMaster === true || licence.clientInfo?.isMaster === true;
    const isValid = licence.isActive && !isExpired;

    // 4. Construction de la réponse
    const result = {
      valid: isValid,
      isMaster,
      expiresAt: licence.expiresAt,
      key,
      licence: {
        ...licence,
        isFirstUse: !licence.used,
        daysRemaining: licence.expiresAt ?
          Math.ceil((new Date(licence.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)) :
          null,
        isExpired
      }
    };

    console.log("\n=== DEBUG VALIDATION END ===");
    console.log("Résultat final:", JSON.stringify(result, null, 2));

    return result;

  } catch (error) {
    console.error("ERREUR DE VALIDATION:", error);
    return { 
      valid: false, 
      reason: 'system_error',
      key,
      details: process.env.NODE_ENV === 'development' ? error.message : null
    };
  }
}

function revokeLicence(key, reason = 'admin-revoked', revokerId = 'system') {
  try {
    const data = loadLicenceData();
    const licenceIndex = data.licences.findIndex(l => l.key === key);

    if (licenceIndex === -1) {
      logLicenceAction('REVOKE_FAIL', { key, error: 'Licence non trouvée' });
      return {
        success: false,
        message: 'Licence non trouvée',
        exists: false,
        key
      };
    }

    const licence = data.licences[licenceIndex];
    const wasAlreadyRevoked = licence.revoked;

    // Mise à jour complète du statut
    licence.revoked = true;
    licence.revokedAt = new Date().toISOString();
    licence.revokedBy = revokerId;
    licence.revokedReason = reason;
    licence.isActive = false;
    licence.deactivatedAt = new Date().toISOString(); // Nouveau champ

    // Mise à jour de la liste des clés révoquées
    if (!data.revokedKeys.includes(key)) {
      data.revokedKeys.push(key);
    }

    if (!saveLicenceData(data)) {
      throw new Error('Échec de sauvegarde des données');
    }

    logLicenceAction('REVOKE_SUCCESS', {
      key,
      revokerId,
      reason,
      wasActive: !wasAlreadyRevoked && licence.isActive,
      previousStatus: {
        revoked: wasAlreadyRevoked,
        active: licence.isActive
      }
    });

    return {
      success: true,
      message: wasAlreadyRevoked 
        ? 'Licence déjà révoquée - Mise à jour effectuée' 
        : 'Licence révoquée et désactivée avec succès',
      key,
      revokedAt: licence.revokedAt,
      wasAlreadyRevoked,
      deactivated: !wasAlreadyRevoked && !licence.isActive
    };

  } catch (error) {
    logLicenceAction('REVOKE_CRITICAL_ERROR', {
      key,
      error: error.message,
      stack: error.stack
    });
    return {
      success: false,
      message: `Erreur critique: ${error.message}`,
      exists: false,
      key
    };
  }
}

function markLicenceUsed(key, userId) {
  try {
    const data = loadLicenceData();
    if (!data) return false;

    const licence = data.licences.find(l => l.key === key);
    if (!licence || !licence.isActive) return false;

    licence.used = true;
    licence.usedAt = new Date().toISOString();
    licence.usedBy = userId;

    if (!saveLicenceData(data)) return false;

    logLicenceAction('LICENCE_USED', {
      key,
      userId,
      durationType: licence.durationType || '1y'
    });
    return true;
  } catch (error) {
    logLicenceAction('LICENCE_USE_ERROR', { key, error: error.message });
    return false;
  }
}

/* ==================== */
/*        EXPORTS       */
/* ==================== */

module.exports = {
  initLicenceSystem,
  generateLicence,
  validateLicence,
  revokeLicence,
  markLicenceUsed,
  getLicenceLogs: loadLicenceLogs,
  getAllLicences: () => loadLicenceData().licences,
  loadLicenceData,
  saveLicenceData
};
