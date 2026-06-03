const rateLimit = require('express-rate-limit');

/**
 * Rate limiter para endpoints de autenticación.
 * Previene ataques de fuerza bruta sobre login, registro y recuperación de contraseña.
 *
 * Para producción real conviene usar un store distribuido (Redis) en lugar del default
 * en memoria, pero para este proyecto el default es suficiente.
 */

// 5 intentos de login por cada 15 minutos por IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Demasiados intentos de inicio de sesión. Inténtalo de nuevo en 15 minutos.'
    },
    // No contar requests exitosos (status < 400) hacia el límite
    skipSuccessfulRequests: true
});

// 3 registros por hora por IP (evita spam de cuentas)
const registroLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Has creado demasiadas cuentas desde esta IP. Inténtalo más tarde.'
    }
});

// 3 solicitudes de recuperación por hora por IP
const recuperarLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Demasiadas solicitudes de recuperación. Inténtalo más tarde.'
    }
});

// Limiter general para el resto de endpoints sensibles (cambio de password, MFA, etc.)
const sensitiveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Demasiadas peticiones. Espera unos minutos.'
    }
});

module.exports = {
    loginLimiter,
    registroLimiter,
    recuperarLimiter,
    sensitiveLimiter
};
