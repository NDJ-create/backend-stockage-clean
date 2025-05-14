module.exports = {
  MASTER_API_KEY: process.env.MASTER_API_KEY,
  BASE_URL: process.env.BASE_URL || 'http://localhost:3001',
  LICENCE_SETTINGS: {
    keyPrefix: 'LIC',
    durations: Object.freeze({ // Rend l'objet immuable
      '1m': 30,
      '2m': 60, 
      '3m': 90,
      '6m': 180,
      '1y': 365,
      'infinite': null
    })
  }
};
