function convertirUnite(quantite, uniteSource, uniteCible) {
  const conversions = {
    'g':    { 'g': 1, 'kg': 0.001, 'unité': 1 },
    'kg':   { 'kg': 1, 'g': 1000,  'unité': 1000 },
    'ml':   { 'ml': 1, 'l': 0.001, 'unité': 1 },
    'l':    { 'l': 1, 'ml': 1000,  'unité': 1000 },
    'unité': { 'unité': 1 },
  };

  if (!uniteSource || !uniteCible) {
    throw new Error(`Unité source ou cible manquante (source: ${uniteSource}, cible: ${uniteCible})`);
  }

  // Normalisation des unités (minuscules, pluriel, alias)
  const normaliser = (u) => {
    u = u.toLowerCase().trim();
    if (['unit', 'unité(s)', 'unites', 'unité'].includes(u)) return 'unité';
    if (u === 'units') return 'unité';
    return u;
  };

  uniteSource = normaliser(uniteSource);
  uniteCible = normaliser(uniteCible);

  // Vérifie que la conversion existe
  if (!conversions[uniteSource]) {
    throw new Error(`Unité source inconnue : ${uniteSource}`);
  }
  if (!conversions[uniteSource][uniteCible]) {
    // Refuser conversions volume ↔ poids sans densité
    const poids = ['g', 'kg'];
    const volume = ['ml', 'l'];
    if (
      (poids.includes(uniteSource) && volume.includes(uniteCible)) ||
      (volume.includes(uniteSource) && poids.includes(uniteCible))
    ) {
      throw new Error(`Conversion impossible entre unités de volume (${uniteSource}) et de poids (${uniteCible}) sans densité.`);
    }
    throw new Error(`Conversion impossible de ${uniteSource} vers ${uniteCible}`);
  }

  return quantite * conversions[uniteSource][uniteCible];
}

function formatDate(date) {
  return date.toISOString();
}

module.exports = {
  convertirUnite,
  formatDate
};
