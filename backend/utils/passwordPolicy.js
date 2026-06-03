/**
 * Validación de complejidad de contraseñas siguiendo recomendaciones OWASP.
 *
 * Requisitos:
 *  - Mínimo 8 caracteres
 *  - Al menos una letra minúscula
 *  - Al menos una letra mayúscula
 *  - Al menos un número
 *  - Al menos un carácter especial
 *  - No puede ser una contraseña común conocida
 */

// Pequeña lista de contraseñas comunes a rechazar de plano.
// En producción conviene usar la lista de Have I Been Pwned (k-anonymity).
const PASSWORDS_COMUNES = new Set([
    'password', '12345678', 'qwerty123', 'admin123', 'password123',
    'contraseña', 'contrasena', '11111111', 'aaaaaaaa', 'abcdefgh',
    'letmein123', 'welcome1', 'iloveyou', '1q2w3e4r', 'password1'
]);

const REQUISITOS = {
    minLength: 8,
    maxLength: 128, // Previene DoS por hash de inputs gigantes
    requireLowercase: /[a-z]/,
    requireUppercase: /[A-Z]/,
    requireNumber: /[0-9]/,
    requireSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/
};

/**
 * Valida una contraseña contra la política.
 * @param {string} password
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validatePassword(password) {
    const errors = [];

    if (typeof password !== 'string') {
        return { valid: false, errors: ['La contraseña debe ser una cadena de texto'] };
    }

    if (password.length < REQUISITOS.minLength) {
        errors.push(`Debe tener al menos ${REQUISITOS.minLength} caracteres`);
    }
    if (password.length > REQUISITOS.maxLength) {
        errors.push(`No puede superar los ${REQUISITOS.maxLength} caracteres`);
    }
    if (!REQUISITOS.requireLowercase.test(password)) {
        errors.push('Debe incluir al menos una letra minúscula');
    }
    if (!REQUISITOS.requireUppercase.test(password)) {
        errors.push('Debe incluir al menos una letra mayúscula');
    }
    if (!REQUISITOS.requireNumber.test(password)) {
        errors.push('Debe incluir al menos un número');
    }
    if (!REQUISITOS.requireSpecial.test(password)) {
        errors.push('Debe incluir al menos un carácter especial (!@#$%^&* etc.)');
    }
    if (PASSWORDS_COMUNES.has(password.toLowerCase())) {
        errors.push('Esta contraseña es demasiado común. Elige otra.');
    }

    return { valid: errors.length === 0, errors };
}

/**
 * Middleware Express que valida la contraseña en req.body.password
 * o req.body.nuevaPassword antes de continuar.
 */
function passwordPolicyMiddleware(req, res, next) {
    const password = req.body.password || req.body.nuevaPassword;
    if (!password) {
        return next(); // Otro middleware se encarga de exigir el campo
    }

    const { valid, errors } = validatePassword(password);
    if (!valid) {
        return res.status(400).json({
            success: false,
            message: 'La contraseña no cumple los requisitos de seguridad',
            errors
        });
    }
    next();
}

module.exports = {
    validatePassword,
    passwordPolicyMiddleware,
    REQUISITOS
};
