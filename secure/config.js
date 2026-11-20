// ============================================================
//  NeoQuetzal API - Configuracion (VERSION CORREGIDA)
//  RS-06: ningun secreto va en el codigo. Todo se lee de
//  variables de entorno (en produccion: AWS Secrets Manager).
// ============================================================
module.exports = {
  JWT_SECRET: process.env.JWT_SECRET,        // obligatorio, inyectado por el entorno
  PORT: process.env.PORT || 3000
};

// Si falta el secreto, la app no arranca (seguro por defecto).
if (!module.exports.JWT_SECRET) {
  console.error("ERROR: falta la variable de entorno JWT_SECRET. La app no inicia.");
  process.exit(1);
}
