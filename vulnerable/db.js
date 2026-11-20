// ============================================================
//  NeoQuetzal API - Base de datos de demostracion (VULNERABLE)
//  Crea una base SQLite con clientes, cuentas y movimientos
//  ficticios para poder probar los ataques.
// ============================================================
const { DatabaseSync } = require("node:sqlite");
const path = require("path");

const db = new DatabaseSync(path.join(__dirname, "neoquetzal.db"));

function seed() {
  db.exec(`
    DROP TABLE IF EXISTS movimientos;
    DROP TABLE IF EXISTS cuentas;
    DROP TABLE IF EXISTS clientes;

    CREATE TABLE clientes (
      id INTEGER PRIMARY KEY,
      usuario TEXT,
      password TEXT,          -- FALLO: contrasenas en texto plano
      nombre TEXT,
      dpi TEXT
    );

    CREATE TABLE cuentas (
      id INTEGER PRIMARY KEY,
      cliente_id INTEGER,
      numero TEXT,
      saldo REAL
    );

    CREATE TABLE movimientos (
      id INTEGER PRIMARY KEY,
      cuenta_id INTEGER,
      fecha TEXT,
      descripcion TEXT,
      monto REAL
    );
  `);

  const clientes = [
    [1, "jperez", "Pollo123", "Juan Perez", "2988112340101"],
    [2, "mlopez", "Flores456", "Maria Lopez", "1874220550108"],
    [3, "crodas", "Quetzal789", "Carlos Rodas", "3011998760114"],
    [4, "admin",  "Admin2026!", "Administrador", "0000000000000"]
  ];
  const insC = db.prepare("INSERT INTO clientes VALUES (?,?,?,?,?)");
  clientes.forEach(c => insC.run(...c));

  const cuentas = [
    [101, 1, "GT-0001-0101", 15230.50],
    [102, 2, "GT-0001-0102", 48900.00],
    [103, 3, "GT-0001-0103", 2750.75],
    [104, 2, "GT-0001-0104", 1200000.00]  // cuenta "jugosa" de otro cliente
  ];
  const insA = db.prepare("INSERT INTO cuentas VALUES (?,?,?,?)");
  cuentas.forEach(a => insA.run(...a));

  const movs = [];
  let id = 1;
  for (const [cid] of cuentas) {
    for (let i = 0; i < 25; i++) {
      movs.push([id++, cid, "2026-10-" + String((i % 28) + 1).padStart(2, "0"),
                 i % 2 ? "Compra en comercio" : "Deposito", (i + 1) * 37.5]);
    }
  }
  const insM = db.prepare("INSERT INTO movimientos VALUES (?,?,?,?,?)");
  movs.forEach(m => insM.run(...m));

  console.log("Base de datos poblada: 4 clientes, 4 cuentas, " + movs.length + " movimientos.");
}

if (require.main === module) seed();

module.exports = db;
