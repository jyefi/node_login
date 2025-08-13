const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const path = require('path');
const fs = require('fs').promises;

const app = express();
app.use(bodyParser.json());

// Datos de conexión
require('dotenv').config();

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
};

// Test connection
(async () => {
  try {
    const testConn = await mysql.createConnection(dbConfig);
    console.log("🔗 Conectando a MySQL...")
    console.log(dbConfig.database);
    console.log(dbConfig.host);
    await testConn.end();
    console.log("✅ Conexión a MySQL exitosa");
  } catch (err) {
    console.error("❌ Error al conectar a MySQL:", err);
  }
})();

app.get("/", async (req, res) => {
  try {
    
    const indexPath = path.join(__dirname, 'index.html');
    const htmlContent = await fs.readFile(indexPath, 'utf8');
    
    res.setHeader('Content-Type', 'text/html');
    res.send(htmlContent);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Función para verificar hash de Django
function verifyDjangoPassword(password, djangoHash) {
  const [algorithm, iterations, salt, hash] = djangoHash.split("$");

  if (algorithm !== "pbkdf2_sha256") {
    throw new Error(`Algoritmo no soportado: ${algorithm}`);
  }

  const derivedKey = crypto.pbkdf2Sync(
    password,
    salt,
    parseInt(iterations, 10),
    32, // longitud clave para sha256
    "sha256"
  );

  const base64Hash = derivedKey.toString("base64");
  return base64Hash === hash;
}

// Endpoint de login
app.post("/login", async (req, res) => {
  // Configurar headers CORS
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');

  const { username, password } = req.body;

  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute(
    "SELECT * FROM auth_user WHERE email = ? AND is_active = 1",
    [username]
  );
  await conn.end();

  if (rows.length === 0) {
    return res.status(401).json({ error: "Usuario no encontrado o inactivo" });
  }

  const user = rows[0];
  if (!verifyDjangoPassword(password, user.password)) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }

  // Aquí podrías generar un token JWT si quieres
  res.json({ message: "Login exitoso", user: { id: user.id, username: user.username, email: user.email } });
});

app.listen(3000, () => console.log("🚀 API corriendo en puerto 3000"));