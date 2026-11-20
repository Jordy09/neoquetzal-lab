// ============================================================
//  NeoQuetzal API - Base de datos de demostracion (CORREGIDA)
//  RS-08: las contrasenas se guardan con hash (scrypt), nunca
//  en texto plano. El usuario de BD seria de menor privilegio.
// ============================================================
const { DatabaseSync } = require("node:sqlite");
const crypto = require("crypto");
const path = require("path");

const db = new DatabaseSync(path.join(__dirname, "neoquetzal_secure.db"));

// hash de contrasena con sal, usando scrypt (incluido en Node, sin dependencias)
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(plain, salt, 64).toString("hex");
  return salt + ":" + hash;
}

function seed() {
  db.exec(`
    DROP TABLE IF EXISTS movimientos;
    DROP TABLE IF EXISTS cuentas;
    DROP TABLE IF EXISTS clientes;
    CREATE TABLE clientes (id INTEGER PRIMARY KEY, usuario TEXT, password TEXT, nombre TEXT, dpi TEXT);
    CREATE TABLE cuentas (id INTEGER PRIMARY KEY, cliente_id INTEGER, numero TEXT, saldo REAL);
    CREATE TABLE movimientos (id INTEGER PRIMARY KEY, cuenta_id INTEGER, fecha TEXT, descripcion TEXT, monto REAL);
  `);

  const clientes = [
    [1, "jperez", hashPassword("Pollo123"), "Juan Perez", "2988112340101"],
    [2, "mlopez", hashPassword("Flores456"), "Maria Lopez", "1874220550108"],
    [3, "crodas", hashPassword("Quetzal789"), "Carlos Rodas", "3011998760114"]
  ];
  const insC = db.prepare("INSERT INTO clientes VALUES (?,?,?,?,?)");
  clientes.forEach(c => insC.run(...c));

  const cuentas = [
    [101, 1, "GT-0001-0101", 15230.50],
    [102, 2, "GT-0001-0102", 48900.00],
    [103, 3, "GT-0001-0103", 2750.75],
    [104, 2, "GT-0001-0104", 1200000.00]
  ];
  const insA = db.prepare("INSERT INTO cuentas VALUES (?,?,?,?)");
  cuentas.forEach(a => insA.run(...a));

  const insM = db.prepare("INSERT INTO movimientos VALUES (?,?,?,?,?)");
  let id = 1;
  for (const [cid] of cuentas)
    for (let i = 0; i < 25; i++)
      insM.run(id++, cid, "2026-10-" + String((i % 28) + 1).padStart(2, "0"),
               i % 2 ? "Compra en comercio" : "Deposito", (i + 1) * 37.5);

  console.log("Base segura poblada (contrasenas con hash).");
}

if (require.main === module) seed();

module.exports = { db, hashPassword };
