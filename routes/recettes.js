const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { convertirUnite, formatDate } = require('../utils');
const { getUserInfo } = require('../helpers.js');
const fs = require('fs');
const { authenticate, licenceCheckMiddleware } = require('../auth');

const {
  loadData,
  saveData,
  generateId,
} = require('../jsonManager');

const { DATA_FILES } = require('../database'); // <- Ajoute l'import vers les chemins JSON
// Configuration Multer spécifique pour ce routeur
const uploadDir = path.join(__dirname, '../uploads');
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const safeName = file.originalname.replace(/[^a-z0-9.]/gi, '_');
      cb(null, `${Date.now()}-${safeName}`);
    }
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Seules les images (JPEG/PNG/WEBP) sont autorisées'));
    }
  }
});

// Middleware pour parser le JSON depuis FormData
const parseRecipeData = (req, res, next) => {
  if (req.body.data) {
    try {
      req.recipeData = JSON.parse(req.body.data);
      next();
    } catch (e) {
      return res.status(400).json({ error: "Format JSON invalide dans le champ 'data'" });
    }
  } else {
    req.recipeData = req.body;
    next();
  }
};

// GET toutes les recettes
// GET toutes les recettes (avec recherche possible par nom)
router.get('/', authenticate, (req, res) => {
  console.log("DEBUG TOKEN:", req.user);
  console.log("DEBUG LICENCE:", req.licence);

  const licenceKey = req.licence?.key;
  const searchTerm = req.query.search?.toLowerCase(); // <- récupère la recherche dans l'URL

  if (!licenceKey) {
    return res.status(500).json({ error: "Licence introuvable dans la requête." });
  }

  try {
    // Chargement des données depuis le fichier main.json
    const data = loadData('main');

    // Récupération de toutes les recettes
    const recettes = data.data?.recettes || [];

    // Filtrage par licence
    let recettesFiltrees = recettes.filter(r => r.licenceKey === licenceKey);

    // Si un terme de recherche est fourni, on filtre aussi par nom de recette
    if (searchTerm) {
      recettesFiltrees = recettesFiltrees.filter(r =>
        r.nom?.toLowerCase().includes(searchTerm)
      );
    }

    // Renvoi des résultats filtrés
    res.json(recettesFiltrees);

  } catch (err) {
    console.error("Erreur GET recettes:", err);
    res.status(500).json({ error: "Erreur serveur lors de la récupération des recettes." });
  }
});

// POST nouvelle recette

router.post('/', authenticate, parseRecipeData, (req, res) => {
  try {
    const licenceKey = req.licence?.key;
    const recipeData = req.recipeData;

    if (!licenceKey) {
      throw new Error("Licence invalide");
    }

    if (!recipeData.nom?.trim() || !recipeData.ingredients) {
      throw new Error("Le nom de la recette et les ingrédients sont obligatoires");
    }

    const ingredients = Array.isArray(recipeData.ingredients)
      ? recipeData.ingredients
      : (() => {
          try {
            return JSON.parse(recipeData.ingredients);
          } catch {
            throw new Error("Format des ingrédients invalide");
          }
        })();

    const normalizedIngredients = ingredients.map(ing => {
      const quantite = parseFloat(ing.quantite);
      const unite = ing.unite?.trim().toLowerCase() || 'unité(s)';

      return {
        ...ing,
        id: parseInt(ing.id),
        nom: ing.nom?.trim() || 'Inconnu',
        quantite: (unite === 'g' || unite === 'ml')
          ? convertirUnite(quantite, unite, unite === 'g' ? 'kg' : 'l')
          : quantite,
        unite: (unite === 'g') ? 'kg' : (unite === 'ml' ? 'l' : unite)
      };
    });

    const data = loadData('main');
    if (!data.data) data.data = {};
    if (!Array.isArray(data.data.recettes)) data.data.recettes = [];
    if (!Array.isArray(data.logs?.actions)) {
      if (!data.logs) data.logs = {};
      data.logs.actions = [];
    }

    const generateId = (arr) => {
      return arr.length === 0 ? 1 : Math.max(...arr.map(item => item.id || 0)) + 1;
    };

    const now = new Date().toISOString();

    const newRecipe = {
      ...recipeData,
      id: generateId(data.data.recettes),
      prix: parseFloat(recipeData.prix) || 0,
      ingredients: normalizedIngredients,
      image: recipeData.image || null,
      user: req.user.userId,
      licenceKey,
      createdAt: now,
      updatedAt: now
    };

    data.data.recettes.push(newRecipe);

    // ✅ Ajout du rôle utilisateur dans les logs
    const userInfo = getUserInfo(req.user.userId, licenceKey);

    data.logs.actions.push({
      id: generateId(data.logs.actions),
      timestamp: now,
      action: 'CREATE_RECETTE',
      user: userInfo
        ? { id: userInfo.id, role: userInfo.role }
        : { id: req.user.userId, role: 'inconnu' },
      licenceKey,
      details: {
        recetteId: newRecipe.id,
        nom: newRecipe.nom,
        prix: newRecipe.prix,
        ingredients: newRecipe.ingredients
      }
    });

    saveData('main', data);

    res.status(201).json({
      success: true,
      data: newRecipe
    });

  } catch (error) {
    console.error('[ERREUR] recette:', error);
    res.status(400).json({ success: false, error: error.message });
  }
});
// PUT mise à jour recette
router.put('/:id/update', authenticate, parseRecipeData, (req, res) => {
  try {
    const licenceKey = req.licence?.key;
    const recetteId = parseInt(req.params.id);
    const updateStock = req.query.updateStock === 'true';

    if (!licenceKey) {
      throw new Error("Licence invalide");
    }

    const data = loadData('main');
    const recipeData = req.recipeData;

    const recipeIndex = data.data.recettes.findIndex(
      r => r.id === recetteId && r.licenceKey === licenceKey
    );

    if (recipeIndex === -1) {
      throw new Error('Recette non trouvée');
    }

    if (updateStock) {
      const ingredients = Array.isArray(recipeData.ingredients)
        ? recipeData.ingredients
        : [];

      for (const ing of ingredients) {
        const item = data.data.stock.find(i =>
          i.id === parseInt(ing.id) && i.licenceKey === licenceKey
        );

        if (!item) throw new Error(`Ingrédient ${ing.nom} absent du stock`);

        if (item.quantite < parseFloat(ing.quantite || 0)) {
          throw new Error(`Stock insuffisant pour ${item.nom}`);
        }
      }
    }

    const updatedRecipe = {
      ...data.data.recettes[recipeIndex],
      ...recipeData,
      id: recetteId,
      prix: parseFloat(recipeData.prix) || data.data.recettes[recipeIndex].prix,
      ingredients: Array.isArray(recipeData.ingredients)
        ? recipeData.ingredients.map(ing => ({
            id: parseInt(ing.id) || 0,
            nom: ing.nom || 'Inconnu',
            quantite: parseFloat(ing.quantite) || 0,
            unite: ing.unite || 'unité(s)'
          }))
        : data.data.recettes[recipeIndex].ingredients,
      image: recipeData.image || data.data.recettes[recipeIndex].image,
      updatedAt: new Date().toISOString(),
      licenceKey
    };

    data.data.recettes[recipeIndex] = updatedRecipe;

    // ✅ Ajout du rôle dans les logs
    const userInfo = getUserInfo(req.user.userId, licenceKey);

    data.logs ??= {};
    data.logs.actions ??= [];

    data.logs.actions.push({
      id: generateId(data.logs.actions),
      timestamp: new Date().toISOString(),
      action: 'UPDATE_RECETTE',
      user: userInfo
        ? { id: userInfo.id, role: userInfo.role }
        : { id: req.user.userId, role: 'inconnu' },
      licenceKey,
      details: {
        recetteId: recetteId,
        nom: updatedRecipe.nom,
        ingredients: updatedRecipe.ingredients,
        prix: updatedRecipe.prix
      }
    });

    saveData('main', data);

    res.json(updatedRecipe);

  } catch (error) {
    console.error('Erreur PUT recette:', error);
    res.status(400).json({ error: error.message });
  }
});

// DELETE recette
router.delete('/:id', authenticate, (req, res) => {
  try {
    const licenceKey = req.licence?.key;
    const recetteId = parseInt(req.params.id);

    if (!licenceKey) {
      return res.status(400).json({ error: 'Licence invalide' });
    }

    const data = loadData('main');

    const recetteIndex = data.data.recettes.findIndex(
      r => r.id === recetteId && r.licenceKey === licenceKey
    );

    if (recetteIndex === -1) {
      return res.status(404).json({ error: 'Recette non trouvée' });
    }

    const deleted = data.data.recettes.splice(recetteIndex, 1);

    // 🔍 Ajout du rôle dans l’historique
    const userInfo = getUserInfo(req.user.userId, licenceKey);

    data.logs ??= {};
    data.logs.actions ??= [];

    data.logs.actions.push({
      id: generateId(data.logs.actions),
      timestamp: new Date().toISOString(),
      action: 'DELETE_RECETTE',
      user: userInfo
        ? { id: userInfo.id, role: userInfo.role }
        : { id: req.user.userId, role: 'inconnu' },
      licenceKey,
      details: {
        recetteId: recetteId,
        nom: deleted[0]?.nom || null
      }
    });

    saveData('main', data);

    res.json({
      success: true,
      message: 'Recette supprimée avec succès',
      deletedId: recetteId,
      deletedNom: deleted[0]?.nom || null
    });

  } catch (error) {
    console.error('Erreur DELETE recette:', error);
    res.status(500).json({ error: error.message });
  }
});
// POST recette avec mise à jour du stock
router.post('/avec-stock', authenticate, async (req, res) => {
  try {
    const licenceKey = req.licence?.key;
    const recipeData = req.body;

    if (!licenceKey) throw new Error("Licence invalide");
    if (!recipeData.nom?.trim() || !recipeData.ingredients)
      throw new Error("Le nom de la recette et les ingrédients sont obligatoires");

    const data = loadData('main');
    if (!data.data) data.data = {};
    if (!Array.isArray(data.data.recettes)) data.data.recettes = [];
    if (!Array.isArray(data.data.stock)) data.data.stock = [];
    if (!data.logs) data.logs = {};
    if (!Array.isArray(data.logs.actions)) data.logs.actions = [];
    if (!Array.isArray(data.data.mouvements)) data.data.mouvements = [];

    const ingredients = Array.isArray(recipeData.ingredients)
      ? recipeData.ingredients
      : (() => {
          try {
            return JSON.parse(recipeData.ingredients);
          } catch {
            throw new Error("Ingrédients mal formatés");
          }
        })();

    if (!Array.isArray(ingredients) || ingredients.length === 0) {
      throw new Error("La recette doit contenir au moins un ingrédient");
    }

    const validatedIngredients = ingredients.map(ing => {
      const quantite = parseFloat(ing.quantite);
      const unite = ing.unite?.trim().toLowerCase();
      if (!unite) throw new Error(`Unité manquante pour ${ing.nom}`);
      if (isNaN(quantite)) throw new Error(`Quantité invalide pour ${ing.nom}`);

      return {
        id: parseInt(ing.id),
        nom: ing.nom?.trim() || 'Inconnu',
        quantite: (unite === 'g' || unite === 'ml')
          ? convertirUnite(quantite, unite, unite === 'g' ? 'kg' : 'l')
          : quantite,
        unite: (unite === 'g') ? 'kg' : (unite === 'ml' ? 'l' : unite)
      };
    });

    const stockUpdates = validatedIngredients.map(ing => {
      const stockItem = data.data.stock.find(item =>
        item.id === ing.id && item.licenceKey === licenceKey
      );
      if (!stockItem) throw new Error(`Ingrédient ${ing.nom} non trouvé dans le stock`);

      const qteRequiseConvertie = ing.quantite;
      if (stockItem.quantite < qteRequiseConvertie) {
        throw new Error(`Stock insuffisant pour ${ing.nom}`);
      }

      return { item: stockItem, quantite: qteRequiseConvertie };
    });

    const now = new Date();
    const newRecipe = {
      id: generateId(data.data.recettes),
      nom: recipeData.nom,
      prix: parseFloat(recipeData.prix) || 0,
      image: recipeData.image || null,
      description: recipeData.description?.trim() || '',
      categorie: recipeData.categorie?.trim() || '',
      ingredients: validatedIngredients,
      licenceKey,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      user: req.user.userId
    };

    // ✅ Mise à jour du stock
    stockUpdates.forEach(({ item, quantite }) => {
      item.quantite -= quantite;
    });

    // ✅ Ajouter dans mouvements avec unité et idProduit
    stockUpdates.forEach(({ item, quantite }) => {
      data.data.mouvements.push({
        id: generateId(data.data.mouvements),
        date: now.toISOString(),
        type: 'utilisation',
        produit: item.nom,
        quantite,
        unite: item.unite,            // ✅ Ajouté
        idProduit: item.id,           // ✅ Ajouté
        categorie: item.categorie,
        licenceKey,
        user: {
          id: req.user.userId,
          role: getUserInfo(req.user.userId, licenceKey)?.role || 'inconnu'
        }
      });
    });

    data.data.recettes.push(newRecipe);

    // ✅ Historique général
    const userInfo = getUserInfo(req.user.userId, licenceKey);
    data.logs.actions.push({
      id: generateId(data.logs.actions),
      timestamp: now.toISOString(),
      action: 'ADD_RECETTE',
      user: userInfo
        ? { id: userInfo.id, role: userInfo.role }
        : { id: req.user.userId, role: 'inconnu' },
      licenceKey,
      details: {
        recetteId: newRecipe.id,
        nom: newRecipe.nom,
        description: newRecipe.description,
        categorie: newRecipe.categorie,
        ingredients: newRecipe.ingredients,
        prix: newRecipe.prix
      }
    });

    saveData('main', data);

    res.status(201).json({
      success: true,
      data: newRecipe,
      stockUpdated: stockUpdates.map(u => ({
        id: u.item.id,
        nom: u.item.nom,
        nouveauStock: u.item.quantite,
        unite: u.item.unite
      }))
    });

  } catch (error) {
    console.error('[ERREUR] recettes-avec-stock:', error);
    res.status(400).json({ success: false, error: error.message });
  }
});

module.exports = router;
