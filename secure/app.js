// ============================================================
//  NeoQuetzal API - VERSION CORREGIDA
//  Curso: Seguridad en Aplicaciones - UMG
//  Cada control corresponde a un requisito RS-xx del Entregable 1.
// ============================================================
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { db } = require("./db");
const config = require("./config");

const app = express();
app.use(bodyParser.json());

// RS-05 / caja negra: cabeceras de seguridad (HSTS, CSP, nosniff, etc.)
app.use(helmet());
app.disable("x-powered-by");

// ------------------------------------------------------------
//  RS-02 / RS-07: autenticacion. Token verificado con secreto
//  fuerte (de entorno); el middleware guarda el id real del usuario.
// ------------------------------------------------------------
function auth(req, res, next) {
  const token = (req.headers["authorization"] || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, config.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "No autorizado" });
  }
}

// RS-01: control de propiedad del recurso. Comprueba que la cuenta
// pertenezca al usuario autenticado; si no, 403 (denegar por defecto).
function esDuenoDeCuenta(cuentaId, userId) {
  const c = db.prepare("SELECT cliente_id FROM cuentas WHERE id = ?").get(cuentaId);
  return c && c.cliente_id === userId;
}

// RS-03: limite de intentos de login con bloqueo temporal.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Demasiados intentos. Intente de nuevo mas tarde." }
});

function verifyPassword(plain, stored) {
  const [salt, hash] = stored.split(":");
  const calc = crypto.scryptSync(plain, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(calc));
}

// ------------------------------------------------------------
//  LOGIN  (RS-03 limite de intentos, RS-08 consulta parametrizada)
// ------------------------------------------------------------
app.post("/api/login", loginLimiter, (req, res) => {
  const { usuario, password } = req.body || {};
  if (typeof usuario !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "Datos invalidos" });

  // Consulta PARAMETRIZADA -> inmune a inyeccion SQL
  const cliente = db.prepare("SELECT * FROM clientes WHERE usuario = ?").get(usuario);
  if (!cliente || !verifyPassword(password, cliente.password)) {
    // RS-11: se registra el intento fallido, sin filtrar el motivo exacto
    console.log(`[AUDIT] login fallido usuario=${usuario} ip=${req.ip}`);
    return res.status(401).json({ error: "Credenciales incorrectas" });
  }

  // RS-07: token de vida corta (15 min)
  const token = jwt.sign({ id: cliente.id, usuario: cliente.usuario },
                         config.JWT_SECRET, { expiresIn: "15m" });
  console.log(`[AUDIT] login exitoso usuario=${usuario} ip=${req.ip}`);
  res.json({ token, nombre: cliente.nombre });
});

// ------------------------------------------------------------
//  CONSULTAR CUENTA  (RS-01: verificacion de propiedad)
// ------------------------------------------------------------
app.get("/api/accounts/:id", auth, (req, res) => {
  if (!esDuenoDeCuenta(req.params.id, req.user.id)) {
    console.log(`[AUDIT] acceso denegado user=${req.user.id} cuenta=${req.params.id}`);
    return res.status(403).json({ error: "Acceso denegado" });
  }
  const cuenta = db.prepare("SELECT * FROM cuentas WHERE id = ?").get(req.params.id);
  res.json(cuenta);
});

// ------------------------------------------------------------
//  MOVIMIENTOS  (RS-01 propiedad + tope de paginacion + parametrizada)
// ------------------------------------------------------------
app.get("/api/accounts/:id/movements", auth, (req, res) => {
  if (!esDuenoDeCuenta(req.params.id, req.user.id))
    return res.status(403).json({ error: "Acceso denegado" });

  const limit = Math.min(parseInt(req.query.limit) || 10, 100); // tope de 100
  const movs = db.prepare("SELECT * FROM movimientos WHERE cuenta_id = ? LIMIT ?")
                 .all(req.params.id, limit);
  res.json(movs);
});

// ------------------------------------------------------------
//  TRANSFERENCIA  (RS-01: solo desde una cuenta propia)
// ------------------------------------------------------------
app.post("/api/transfers", auth, (req, res) => {
  const { origen, destino, monto } = req.body || {};
  if (!esDuenoDeCuenta(origen, req.user.id))
    return res.status(403).json({ error: "La cuenta origen no le pertenece" });
  if (!(monto > 0)) return res.status(400).json({ error: "Monto invalido" });

  const cuentaOrigen = db.prepare("SELECT saldo FROM cuentas WHERE id = ?").get(origen);
  if (cuentaOrigen.saldo < monto) return res.status(400).json({ error: "Saldo insuficiente" });

  db.prepare("UPDATE cuentas SET saldo = saldo - ? WHERE id = ?").run(monto, origen);
  db.prepare("UPDATE cuentas SET saldo = saldo + ? WHERE id = ?").run(monto, destino);
  console.log(`[AUDIT] transferencia user=${req.user.id} origen=${origen} monto=${monto}`);
  res.json({ ok: true, mensaje: "Transferencia realizada" });
});

// RS-11: manejador de errores central. No filtra detalles internos.
app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: "Error interno" });
});

app.get("/", (req, res) => res.json({ servicio: "NeoQuetzal API (lab)", version: "secure" }));

app.listen(config.PORT, () => console.log("NeoQuetzal API (SEGURA) en puerto " + config.PORT));
