const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { 
  loadData,
  saveData,
  logAction
} = require('./jsonManager');
const { validateLicence } = require('./licence');
const SECRET_KEY = process.env.SECRET_KEY;
// --------------------------------------
// AUTHENTIFICATION (LOGIN)
// --------------------------------------
async function login(email, password) {
  const data = loadData();
  const user = data.data.users.find(u => u.email === email);

  if (!user) {
    await logAction({
      type: 'LOGIN_FAILED',
      userId: null,
      description: `Tentative de connexion avec email non trouvé: ${email}`,
      details: {}
    });
    throw new Error('Identifiants incorrects');
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    await logAction({
      type: 'LOGIN_FAILED',
      userId: user.id,
      description: `Tentative de connexion avec mot de passe incorrect pour ${email}`,
      details: {}
    });
    throw new Error('Identifiants incorrects');
  }

  // Validation de la licence
  if (user.licenceKey) {
    try {
      await validateUserLicence(user);
    } catch (err) {
      await logAction({
        type: 'LICENCE_VALIDATION_FAILED',
        userId: user.id,
        description: `Échec de validation de la licence pour ${email}`,
        details: { error: err.message }
      });
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

  await logAction({
    type: 'LOGIN_SUCCESS',
    userId: user.id,
    description: `Connexion réussie pour ${user.email}`,
    details: { role: user.role }
  });

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

// --------------------------------------
// RÉINITIALISATION MOT DE PASSE
// --------------------------------------
async function resetPassword(email, newPassword, secretAnswer) {
  const data = loadData();
  const user = data.data.users.find(u => u.email === email);

  if (!user || user.secretAnswer !== secretAnswer) {
    await logAction({
      type: 'PASSWORD_RESET_FAILED',
      userId: user?.id || null,
      description: `Tentative de réinitialisation pour ${email}`,
      details: { reason: !user ? 'User not found' : 'Incorrect secret answer' }
    });
    throw new Error('Réinitialisation impossible');
  }

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  user.lastPasswordUpdate = new Date().toISOString();
  saveData(data);

  await logAction({
    type: 'PASSWORD_RESET',
    userId: user.id,
    description: `Réinitialisation du mot de passe pour ${email}`,
    details: {}
  });

  return true;
}

// --------------------------------------
// VÉRIFICATION DE PERMISSIONS (ROLES)
// --------------------------------------
function requireRole(requiredRoles) {
  return (req, res, next) => {
    if (!requiredRoles.includes(req.user.role)) {
      logAction({
        type: 'UNAUTHORIZED_ACCESS',
        userId: req.user.userId,
        description: `Tentative d'accès non autorisé pour le rôle ${req.user.role}`,
        details: {
          requiredRoles,
          userRole: req.user.role
        }
      });
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
    return res.status(401).json({ error: 'Token manquant' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Format de token invalide' });
  }

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
    next();
  } catch (err) {
    logAction({
      type: 'INVALID_TOKEN',
      userId: null,
      description: `Tentative d'accès avec token invalide`,
      details: { error: err.message }
    });
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

module.exports = {
  login,
  resetPassword,
  authenticate,
  requireRole,
  validateUserLicence,
  SECRET_KEY
};
