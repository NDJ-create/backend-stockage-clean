// migrate.js
const fs = require('fs');
const path = require('path');
const { loadData, saveData } = require('./database');

function migrate() {
  try {
    console.log('Début de la migration...');
    
    // 1. Migration du stock
    const oldData = loadData('main'); // Ancien fichier historique.json
    if (oldData.data?.stock) {
      const newStock = oldData.data.stock.map(item => ({
        ...item,
        licenceKey: item.licenceKey || 'LIC-1-B21585D3' // Valeur par défaut
      }));
      saveData('stock', newStock);
      console.log(`✅ ${newStock.length} éléments migrés vers stock.json`);
    }

    // 2. Migration historique
    const newHistorique = {
      mouvements: oldData.data?.mouvements || [],
      actions: oldData.logs?.actions || []
    };
    saveData('historique', newHistorique);
    console.log(`✅ Historique migré (${newHistorique.mouvements.length} mouvements)`);

    console.log('Migration terminée avec succès !');
  } catch (error) {
    console.error('❌ Erreur lors de la migration:', error);
  }
}

// Exécuter la migration
migrate();
