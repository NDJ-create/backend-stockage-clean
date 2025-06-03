// helpers.js

const { loadData } = require('./jsonManager');

function getUserInfo(userId, licenceKey) {
  const usersData = loadData('users');
  const mainData = loadData('main');

  // SuperAdmin/Admin depuis users.json
  let user;
  if (Array.isArray(usersData)) {
    user = usersData.find(u => u.id === userId && u.licenceKey === licenceKey);
  } else if (usersData.users) {
    user = usersData.users.find(u => u.id === userId && u.licenceKey === licenceKey);
  }

  if (user) {
    return {
      id: user.id,
      nom: user.nom || user.email,
      role: user.role || 'superAdmin'
    };
  }

  // Staff dans main.json
  const staff = mainData.data.staff.find(s => s.id === userId && s.licenceKey === licenceKey);
  if (staff) {
    return {
      id: staff.id,
      nom: staff.nom,
      role: staff.role || 'staff'
    };
  }

  // Si rien trouvé
  return {
    id: userId,
    nom: 'Inconnu',
    role: 'inconnu'
  };
}

module.exports = { getUserInfo };
