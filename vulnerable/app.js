// ============================================================
//  NeoQuetzal API - VERSION VULNERABLE
//  Curso: Seguridad en Aplicaciones - UMG
//  Reproduce a proposito los fallos CB-01 a CB-10 del Entregable 1.
//  NO USAR EN PRODUCCION. Es un laboratorio academico.
// ============================================================
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const db = require("./db");
const config = require("./config");

const app = express();
app.use(bodyParser.json());

// ------------------------------------------------------------
//  Middleware de autenticacion
//  FALLO CB-01 (T-01, T-02): el token se firma con un secreto
//  debil y hardcodeado, y no se verifica expiracion real.
// ------------------------------------------------------------
function auth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, config.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Token invalido" });
  }
}

// ------------------------------------------------------------
//  LOGIN
//  FALLO CB-05 (T-03, R-02): no hay limite de intentos.
//  FALLO CB-06 (T-09): la consulta se arma concatenando texto
//  (inyeccion SQL) y la BD corre con usuario administrador.
// ------------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { usuario, password } = req.body;

  // Consulta construida por concatenacion -> vulnerable a SQLi
  const query = "SELECT * FROM clientes WHERE usuario = '" + usuario +
                "' AND password = '" + password + "'";
  try {
    const cliente = db.prepare(query).get();
    if (!cliente) {
      return res.status(401).json({ error: "Credenciales incorrectas" });
    }
    // Token de larga duracion (24h) con secreto debil
    const token = jwt.sign(
      { id: cliente.id, usuario: cliente.usuario },
      config.JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.json({ token, nombre: cliente.nombre });
  } catch (e) {
    // FALLO (T-17): se devuelve el detalle interno del error al cliente
    res.status(500).json({ error: e.message, query: query });
  }
});

// ------------------------------------------------------------
//  CONSULTAR UNA CUENTA
//  FALLO CB-04 (T-06, R-01) - BOLA/IDOR: usa el id de la URL
//  sin verificar que la cuenta pertenezca al usuario del token.
// ------------------------------------------------------------
app.get("/api/accounts/:id", auth, (req, res) => {
  const cuenta = db.prepare("SELECT * FROM cuentas WHERE id = ?").get(req.params.id);
  if (!cuenta) return res.status(404).json({ error: "No existe" });
  res.json(cuenta); // <- deberia comprobar cuenta.cliente_id === req.user.id
});

// ------------------------------------------------------------
//  MOVIMIENTOS DE UNA CUENTA
//  FALLO CB-04 (T-06) de nuevo + exfiltracion masiva por
//  paginacion: 'limit' no tiene tope, se puede pedir todo.
// ------------------------------------------------------------
app.get("/api/accounts/:id/movements", auth, (req, res) => {
  const limit = req.query.limit || 10;   // sin tope -> ?limit=999999 trae todo
  const movs = db.prepare(
    "SELECT * FROM movimientos WHERE cuenta_id = " + req.params.id +
    " LIMIT " + limit                    // concatenacion -> SQLi tambien aqui
  ).all();
  res.json(movs);
});

// ------------------------------------------------------------
//  TRANSFERENCIA
//  FALLO CB-04 (T-07, R-01): debita de 'origen' sin verificar
//  que esa cuenta sea del usuario autenticado.
// ------------------------------------------------------------
app.post("/api/transfers", auth, (req, res) => {
  const { origen, destino, monto } = req.body;
  const cuentaOrigen = db.prepare("SELECT * FROM cuentas WHERE id = ?").get(origen);
  if (!cuentaOrigen) return res.status(404).json({ error: "Cuenta origen no existe" });

  // No se valida cuentaOrigen.cliente_id === req.user.id
  db.prepare("UPDATE cuentas SET saldo = saldo - ? WHERE id = ?").run(monto, origen);
  db.prepare("UPDATE cuentas SET saldo = saldo + ? WHERE id = ?").run(monto, destino);
  res.json({ ok: true, mensaje: "Transferencia realizada" });
});

// ------------------------------------------------------------
//  LISTAR TODOS LOS CLIENTES (endpoint administrativo sin control)
//  FALLO: ruta sensible sin verificacion de rol.
// ------------------------------------------------------------
app.get("/api/clientes", auth, (req, res) => {
  const todos = db.prepare("SELECT id, usuario, nombre, dpi FROM clientes").all();
  res.json(todos);
});

app.get("/", (req, res) => res.json({ servicio: "NeoQuetzal API (lab)", version: "vulnerable" }));

app.listen(config.PORT, () => {
  console.log("NeoQuetzal API (VULNERABLE) escuchando en http://localhost:" + config.PORT);
});
