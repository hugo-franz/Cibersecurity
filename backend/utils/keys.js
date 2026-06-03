const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Gestión de par de claves RSA para firmas digitales.
 * Si las claves no existen en disco, las genera y persiste con permisos restrictivos.
 * Si ya existen, simplemente las carga.
 */

const KEYS_DIR = path.join(__dirname, '../../keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'signing-private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'signing-public.pem');

let privateKey = null;
let publicKey = null;

/**
 * Inicializa el par de claves RSA. Se debe llamar UNA vez al arrancar el servidor.
 * @returns {{ publicKey: string, privateKey: string }}
 */
function initKeyPair() {
    // Asegurar que existe el directorio
    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    }

    // Si ya existen, cargarlas
    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
        privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
        publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
        console.log('[KEYS] Par de claves RSA cargado desde disco.');
        return { publicKey, privateKey };
    }

    // Si no existen, generarlas
    console.log('[KEYS] Generando nuevo par de claves RSA-2048...');
    const keyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    // Persistir con permisos restrictivos (solo lectura para el dueño)
    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });

    console.log('[KEYS] Par de claves RSA generado y guardado.');
    return { publicKey, privateKey };
}

function getPrivateKey() {
    if (!privateKey) {
        throw new Error('Las claves no han sido inicializadas. Llama a initKeyPair() al arrancar el servidor.');
    }
    return privateKey;
}

function getPublicKey() {
    if (!publicKey) {
        throw new Error('Las claves no han sido inicializadas. Llama a initKeyPair() al arrancar el servidor.');
    }
    return publicKey;
}

/**
 * Construye la cadena canónica que se firma para una reserva.
 * Importante: el orden de los campos debe ser fijo para que la verificación coincida.
 */
function canonicalReservaPayload(reserva) {
    return [
        reserva.id_reservacion,
        reserva.id_usuario,
        reserva.id_cancha,
        reserva.fecha,
        reserva.hora_inicio,
        reserva.duracion_minutos
    ].join('|');
}

module.exports = {
    initKeyPair,
    getPrivateKey,
    getPublicKey,
    canonicalReservaPayload
};
