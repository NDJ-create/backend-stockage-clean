require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const {
  loadData,
  saveData,
  logAction
} = require('./jsonManager');
const SECRET_KEY = process.env.SECRET_KEY;
// --------------------------------------
// AUTHENTIFICATION (LOGIN)
// --------------------------------------
async function login(email, password) {
  const data = loadData();
  const user = data.data.users.find(u => u.email === email);

  if (!user) {
    await logAction('LOGIN_FAILED', {
      user: null,
      description: `Tentative de connexion avec email non enregistré: ${email}`
    }, null);
    throw new Error('Identifiants incorrects');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    await logAction('LOGIN_FAILED', {
      user: user.id,
      description: `Tentative de connexion avec mot de passe incorrect pour ${email}`
    }, user.licenceKey || null);
    throw new Error('Identifiants incorrects');
  }

  // Validation de la licence
  if (user.licenceKey) {
    try {
      await validateUserLicence(user);
    } catch (err) {
      await logAction('LICENCE_VALIDATION_FAILED', {
        user: user.id,
        description: `Échec de validation de la licence pour ${email}`,
        error: err.message
      }, user.licenceKey || null);
      throw err;
    }
  }

  const token = jwt.sign(
    {
      userId: user.id,
      role: user.role,
      email: user.email,
      licenceKey: user.licenceKey || null
    },
    SECRET_KEY,
    { expiresIn: '24h' }
  );

  await logAction('LOGIN_SUCCESS', {
    user: user.id,
    description: `Connexion réussie pour ${user.email}`,
    role: user.role
  }, user.licenceKey || null);

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      licenceKey: user.licenceKey || null
    }
  };
}

// --------------------------------------
// VALIDATION DE LICENCE UTILISATEUR
// --------------------------------------
async function validateUserLicence(user) {
  if (!user.licenceKey) return false;

  const validation = validateLicence(user.licenceKey);
  if (!validation.valid) {
    throw new Error(`Licence ${validation.reason}`);
  }

  return validation.licence;
}

// Fonction de validation de licence
function validateLicence(licenceKey) {
  const licenceData = loadData('licences');
  const licence = licenceData.licences?.find(l => l.key === licenceKey);

  if (!licence) {
    return { valid: false, reason: 'non trouvée' };
  }

  if (licence.revoked) {
    return { valid: false, reason: 'révoquée' };
  }

  // Ne pas vérifier la date d'expiration pour les licences master
  if (!licence.isMaster && new Date(licence.expiresAt) < new Date()) {
    return { valid: false, reason: 'expirée' };
  }

  return {
    valid: true,
    isMaster: licence.isMaster,
    licence
  };
}

// --------------------------------------
// RÉINITIALISATION MOT DE PASSE
// --------------------------------------
async function resetPassword(email, newPassword, secretAnswer) {
  const data = loadData();
  const user = data.data.users.find(u => u.email === email);

  if (!user || user.secretAnswer !== secretAnswer) {
    await logAction('PASSWORD_RESET_FAILED', {
      user: user?.id || null,
      description: `Tentative de réinitialisation pour ${email}`,
      reason: !user ? 'Utilisateur introuvable' : 'Réponse secrète incorrecte'
    }, user?.licenceKey || null);

    throw new Error('Réinitialisation impossible');
  }

  user.password = await bcrypt.hash(newPassword, 10);
  user.lastPasswordUpdate = new Date().toISOString();
  saveData('main', data);
  await logAction('PASSWORD_RESET', {
    user: user.id,
    description: `Réinitialisation du mot de passe pour ${email}`
  }, user.licenceKey || null);

  return true;
}

// --------------------------------------
// VÉRIFICATION DE PERMISSIONS (ROLES)
// --------------------------------------
function requireRole(requiredRoles) {
  return (req, res, next) => {
    if (!requiredRoles.includes(req.user.role)) {
      logAction('UNAUTHORIZED_ACCESS', {
        user: req.user.userId,
        description: `Tentative d'accès non autorisé pour ${req.user.email}`,
        requiredRoles,
        userRole: req.user.role
      }, req.user.licenceKey || null);

      return res.status(403).json({ error: 'Permissions insuffisantes' });
    }
    next();
  };
}

// --------------------------------------
// MIDDLEWARE D'AUTHENTIFICATION
// --------------------------------------
function authenticate(req, res, next) {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    return res.status(401).json({
      error: 'Token manquant',
      code: 'MISSING_TOKEN'
    });
  }

  const parts = authHeader.split(' ');

  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      error: 'Format de token invalide',
      code: 'INVALID_TOKEN_FORMAT'
    });
  }

  const token = parts[1];

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
    req.licence = { key: verified.licenceKey || null };
    next();
  } catch (err) {
    logAction('INVALID_TOKEN', {
      user: 'unknown',
      description: `Tentative d'accès avec token invalide`,
      error: err.message
    }, null);

    res.status(401).json({
      error: 'Token invalide ou expiré',
      code: 'INVALID_TOKEN'
    });
  }
}
// --------------------------------------
// VÉRIFICATION DE LICENCE
// --------------------------------------
async function licenceCheckMiddleware(req, res, next) {
  try {
    const licenceKey = req.headers['x-licence-key'] || req.user?.licenceKey;

    if (!licenceKey) {
      return res.status(400).json({
        error: 'LicenceKey manquante',
        code: 'MISSING_LICENCE_KEY'
      });
    }

    const validation = validateLicence(licenceKey);
    if (!validation.valid) {
      return res.status(403).json({
        error: `Licence ${validation.reason}`,
        code: 'INVALID_LICENCE'
      });
    }

    req.licence = {
      key: licenceKey,
      data: validation.licence,
      isMaster: validation.isMaster
    };
    next();
  } catch (error) {
    console.error('Erreur licenceCheckMiddleware:', error);
    res.status(500).json({
      error: 'Erreur de vérification de licence',
      code: 'LICENCE_CHECK_ERROR'
    });
  }
}

// --------------------------------------
// VÉRIFICATION LICENCE MASTER
// --------------------------------------
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

module.exports = {
  login,
  resetPassword,
  validateUserLicence,
  authenticate,
  requireRole,
  licenceCheckMiddleware,
  masterLicenceRequired,
  validateLicence
};

