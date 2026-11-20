// ============================================================
//  NeoQuetzal API - Configuracion (VERSION VULNERABLE)
// ============================================================
//  FALLO CB-03 / CB-09 (amenazas T-05, T-13):
//  Secretos, llaves de API y credenciales escritos directamente
//  en el codigo fuente. Cualquiera con acceso al repositorio o
//  que haga ingenieria inversa del APK los obtiene.
//  Esto es EXACTAMENTE lo que un escaneo de secretos (Gitleaks)
//  y el SAST (Semgrep) deben detectar.
// ============================================================

module.exports = {
  // Secreto con el que se firman los tokens JWT (debilisimo y expuesto)
  JWT_SECRET: "neoquetzal123",

  // "API key" del proveedor de notificaciones push, embebida en el cliente
  PUSH_API_KEY: "sk_live_51NqZalPushKeyHardcoded0000ABCDEF",

  // Credenciales de la base de datos: usuario administrador (FALLO CB-06)
  DB_USER: "admin",
  DB_PASSWORD: "Admin2026!",

  // Credenciales de AWS hardcodeadas (patron tipico que detectan los escaneres)
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",

  // Cadena de conexion completa, tambien expuesta
  DATABASE_URL: "postgres://admin:Admin2026!@db.neoquetzal.internal:5432/core",

  PORT: 3000
};
