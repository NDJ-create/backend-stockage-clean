const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'data/historique.json');
const LICENCES_VALIDES = ["LIC-1-B21585D3", "LIC-3-E70A6650", "LIC-4-1AFFD54A"];

function migrateSection(section) {
  return (section || []).map(item => ({
    ...item,
    licenceKey: item.licenceKey || LICENCES_VALIDES[0]
  }));
}

function migrate() {
  console.log("🔍 Début de la migration...");
  const data = JSON.parse(fs.readFileSync(filePath));

  // Migration des sections
  data.data.stock = migrateSection(data.data.stock);
  data.data.commandes = migrateSection(data.data.commandes);
  data.data.recettes = migrateSection(data.data.recettes);
  data.data.ventes = migrateSection(data.data.ventes);
  data.data.rapports = {
    ventes: migrateSection(data.data.rapports?.ventes),
    depenses: migrateSection(data.data.rapports?.depenses),
    benefices: migrateSection(data.data.rapports?.benefices)
  };
  data.logs.actions = migrateSection(data.logs?.actions);

  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  console.log("📊 Résumé :");
  console.log(`- Stock : ${data.data.stock.length} items migrés`);
  console.log(`- Logs : ${data.logs.actions.length} actions traitées`);
}

// --------------------------
// POINT D'ENTRÉE PRINCIPAL
// --------------------------
try {
  migrate(); // <-- LIGNE CLÉ
  console.log("✅ Tout est prêt !");
} catch (err) {
  console.error("❌ Crash pendant la migration :", err);
  process.exit(1);
}
