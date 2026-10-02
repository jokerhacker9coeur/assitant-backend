const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ==================== MIDDLEWARE AUTH ====================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ error: 'Token manquant' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide ou expiré' });
    }
    req.userId = decoded.id;
    req.userEmail = decoded.email;
    next();
  });
}

// ==================== UTILITAIRE ====================
// Convertit une ligne SQL (snake_case) en objet frontend (camelCase)
function formatUser(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    profileTypeId: row.profile_type_id,
    profileSelected: row.profile_selected,
    besoinsSpecifiques: row.besoins_specifiques,
  };
}

// ==================== ROUTE DE TEST ====================
app.get('/', (req, res) => {
  res.json({ message: 'API Assistant opérationnelle 🚀' });
});

// ==================== AUTHENTIFICATION ====================
// Inscription
app.post('/api/auth/register', async (req, res) => {
  // ⚡ Accepte fullName (camelCase) OU full_name (snake_case)
  const fullName = req.body.fullName || req.body.full_name;
  const { email, password } = req.body;

  if (!fullName || !email || !password) {
    return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Cet email est déjà utilisé' });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (full_name, email, password_hash) 
       VALUES ($1, $2, $3) 
       RETURNING id, full_name, email, profile_type_id, profile_selected, besoins_specifiques`,
      [fullName, email, hash]
    );

    const user = formatUser(result.rows[0]);
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '30d',
    });

    res.json({ user, token });
  } catch (err) {
    console.error('Erreur register:', err);
    res.status(500).json({ error: err.message });
  }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, password_hash, profile_type_id, profile_selected, besoins_specifiques 
       FROM users WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const row = result.rows[0];
    const isValid = await bcrypt.compare(password, row.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const user = formatUser(row);
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '30d',
    });

    res.json({ user, token });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: err.message });
  }
});

// ⚡ NOUVEAU : Restaurer la session au démarrage de l'app
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, profile_type_id, profile_selected, besoins_specifiques 
       FROM users WHERE id = $1`,
      [req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    res.json({ user: formatUser(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== UTILISATEURS ====================
app.get('/api/users/email/:email', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, full_name, email, profile_type_id, profile_selected, besoins_specifiques FROM users WHERE email = $1',
      [req.params.email]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json(formatUser(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== CONVERSATIONS ====================
app.get('/api/conversations/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, created_at, updated_at 
       FROM conversations 
       WHERE user_id = $1 
       ORDER BY updated_at DESC`,
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/conversations', async (req, res) => {
  const { user_id, title } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO conversations (user_id, title) 
       VALUES ($1, $2) 
       RETURNING *`,
      [user_id, title || 'Nouvelle discussion']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/conversations/:id', async (req, res) => {
  const { title } = req.body;
  try {
    const result = await pool.query(
      `UPDATE conversations 
       SET title = $1, updated_at = NOW() 
       WHERE id = $2 
       RETURNING *`,
      [title, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/conversations/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM conversations WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Conversation non trouvée' });
    }
    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== MESSAGES ====================
app.get('/api/conversations/:conversationId/messages', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, sender, message, via_voice, created_at 
       FROM chat_messages 
       WHERE conversation_id = $1 
       ORDER BY created_at ASC`,
      [req.params.conversationId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/messages', async (req, res) => {
  const { conversation_id, user_id, sender, message, via_voice } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO chat_messages (conversation_id, user_id, sender, message, via_voice) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING *`,
      [conversation_id, user_id, sender, message, via_voice || false]
    );
    await pool.query(
      'UPDATE conversations SET updated_at = NOW() WHERE id = $1',
      [conversation_id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== TÂCHES ====================
app.get('/api/tasks/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, label, scheduled_at, reminder_enabled, done, completed_at, created_at, priority 
       FROM tasks 
       WHERE user_id = $1 
       ORDER BY 
         CASE priority 
           WHEN 'urgent' THEN 1 
           WHEN 'moyen' THEN 2 
           ELSE 3 
         END, 
         done ASC, 
         scheduled_at ASC NULLS LAST`,
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tasks', async (req, res) => {
  const { user_id, label, scheduled_at, reminder_enabled, priority } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO tasks (user_id, label, scheduled_at, reminder_enabled, priority, done) 
       VALUES ($1, $2, $3, $4, $5, false) 
       RETURNING *`,
      [user_id, label, scheduled_at, reminder_enabled !== false, priority || 'normal']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tasks/:id/toggle', async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE tasks 
       SET done = NOT done, 
           completed_at = CASE WHEN NOT done THEN NOW() ELSE NULL END
       WHERE id = $1 
       RETURNING *`,
      [req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== PROFIL ====================
app.get('/api/profile-type', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, full_name, email, profile_type_id, profile_selected, besoins_specifiques FROM users WHERE id = $1',
      [req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    res.json(formatUser(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/profile-type', authenticateToken, async (req, res) => {
  const { profileTypeId, besoinsSpecifiques } = req.body;

  if (!profileTypeId) {
    return res.status(400).json({ error: 'profileTypeId est requis' });
  }

  try {
    const result = await pool.query(
      `UPDATE users 
       SET profile_type_id = $1, 
           profile_selected = TRUE,
           besoins_specifiques = $2,
           updated_at = NOW()
       WHERE id = $3 
       RETURNING id, full_name, email, profile_type_id, profile_selected, besoins_specifiques`,
      [profileTypeId, besoinsSpecifiques || null, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json(formatUser(result.rows[0]));
  } catch (err) {
    console.error('Erreur profile-type:', err);
    res.status(500).json({ error: err.message });
  }
});

// ==================== DÉMARRAGE ====================
const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API démarrée sur http://0.0.0.0:${PORT}`);
});