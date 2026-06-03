const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/database');
const crypto = require('crypto');
const passport = require('passport');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { encrypt, decrypt, hashData, verifyHash, sanitizeInput } = require('../utils/security');

require('../config/passport');

// Generar token CSRF
router.get('/csrf-token', (req, res) => {
    const csrfToken = crypto.randomBytes(32).toString('hex');
    res.cookie('csrfToken', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ csrfToken });
});

// Registro de usuario
router.post('/registro', async (req, res) => {
    try {
        const { nombre, apellido, telefono, email, password } = req.body;

        // Validar campos requeridos
        if (!nombre || !apellido || !telefono || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Todos los campos son requeridos' 
            });
        }

        // Sanitizar inputs
        const nombreSanitizado = sanitizeInput(nombre);
        const apellidoSanitizado = sanitizeInput(apellido);
        const telefonoSanitizado = sanitizeInput(telefono);
        const emailSanitizado = email ? sanitizeInput(email) : null;

        // Cifrar email si existe
        const emailCifrado = emailSanitizado ? encrypt(emailSanitizado) : null;

        // Verificar si el teléfono ya existe
        const [existingUser] = await pool.query(
            'SELECT id_usuario FROM usuarios WHERE telefono = ?',
            [telefonoSanitizado]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'El teléfono ya está registrado' 
            });
        }

        // Hashear contraseña
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        // Insertar usuario
        const [result] = await pool.query(
            'INSERT INTO usuarios (nombre, apellido, telefono, email, password_hash, id_rol) VALUES (?, ?, ?, ?, ?, 2)',
            [nombreSanitizado, apellidoSanitizado, telefonoSanitizado, emailCifrado, password_hash]
        );

        res.status(201).json({ 
            success: true, 
            message: 'Usuario registrado exitosamente' 
        });

    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al registrar usuario' 
        });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { telefono, password } = req.body;

        // Validar campos
        if (!telefono || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Teléfono y contraseña son requeridos' 
            });
        }

        // Buscar usuario
        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE telefono = ? AND activo = TRUE',
            [telefono]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }

        const user = users[0];

        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }

        // Verificar si MFA está habilitado
        if (user.mfa_enabled) {
            return res.json({ 
                success: true, 
                mfaRequired: true,
                message: 'Se requiere código MFA'
            });
        }

        // Descifrar email si existe
        const emailDescifrado = user.email ? decrypt(user.email) : null;

        // Generar token
        const token = jwt.sign(
            { 
                id_usuario: user.id_usuario, 
                telefono: user.telefono,
                rol: user.id_rol 
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Guardar sesión en base de datos
        const expiracion = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await pool.query(
            'INSERT INTO sesiones (id_usuario, token, expiracion) VALUES (?, ?, ?)',
            [user.id_usuario, token, expiracion]
        );

        // Enviar token en cookie segura
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000, // 24 horas
            path: '/'
        });

        // Enviar datos de usuario en respuesta
        res.json({ 
            success: true, 
            message: 'Login exitoso',
            user: {
                id_usuario: user.id_usuario,
                nombre: user.nombre,
                apellido: user.apellido,
                telefono: user.telefono,
                email: emailDescifrado,
                rol: user.id_rol
            }
        });

    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al iniciar sesión' 
        });
    }
});

// Recuperar contraseña
router.post('/recuperar', async (req, res) => {
    try {
        const { telefono, email } = req.body;

        // Validar campos
        if (!telefono) {
            return res.status(400).json({ 
                success: false, 
                message: 'El teléfono es requerido' 
            });
        }

        // Buscar usuario
        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE telefono = ? AND activo = TRUE',
            [telefono]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'No se encontró usuario con ese teléfono' 
            });
        }

        const user = users[0];

        // Generar token de recuperación
        const resetToken = jwt.sign(
            { id_usuario: user.id_usuario },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // En una implementación real, aquí se enviaría un email con el token
        // Por ahora, retornamos el token para demostración
        res.json({ 
            success: true, 
            message: 'Token de recuperación generado',
            resetToken,
            info: 'En producción, este token se enviaría por email'
        });

    } catch (error) {
        console.error('Error en recuperación:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al procesar recuperación' 
        });
    }
});

// Restablecer contraseña
router.post('/restablecer', async (req, res) => {
    try {
        const { token, nuevaPassword } = req.body;

        // Validar campos
        if (!token || !nuevaPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Token y nueva contraseña son requeridos' 
            });
        }

        // Verificar token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Hashear nueva contraseña
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(nuevaPassword, salt);

        // Actualizar contraseña
        await pool.query(
            'UPDATE usuarios SET password_hash = ? WHERE id_usuario = ?',
            [password_hash, decoded.id_usuario]
        );

        res.json({ 
            success: true, 
            message: 'Contraseña actualizada exitosamente' 
        });

    } catch (error) {
        console.error('Error al restablecer:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al restablecer contraseña' 
        });
    }
});

// Logout
router.post('/logout', async (req, res) => {
    try {
        const token = req.cookies.token || req.body.token;

        // Eliminar sesión de base de datos
        if (token) {
            await pool.query(
                'DELETE FROM sesiones WHERE token = ?',
                [token]
            );
        }

        // Limpiar cookie
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/'
        });

        res.json({ 
            success: true, 
            message: 'Sesión cerrada exitosamente' 
        });

    } catch (error) {
        console.error('Error en logout:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al cerrar sesión' 
        });
    }
});

// Middleware para verificar CSRF
const verifyCSRF = (req, res, next) => {
    const csrfToken = req.cookies.csrfToken || req.headers['x-csrf-token'];
    const clientCSRF = req.body._csrf || req.headers['x-csrf-token'];
    
    if (!csrfToken || !clientCSRF || csrfToken !== clientCSRF) {
        return res.status(403).json({ success: false, message: 'Error de validación CSRF' });
    }
    
    next();
};

// Middleware para verificar token
const verifyToken = async (req, res, next) => {
    // Intentar obtener token de cookie primero, luego de header
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Token no proporcionado' });
    }
    
    try {
        // Verificar token JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Verificar que la sesión existe en la base de datos
        const [sesiones] = await pool.query(
            'SELECT * FROM sesiones WHERE token = ? AND expiracion > NOW()',
            [token]
        );
        
        if (sesiones.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Sesión expirada o inválida. Por favor inicia sesión nuevamente.' 
            });
        }
        
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Error al verificar token:', error);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token expirado. Por favor inicia sesión nuevamente.' 
            });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token inválido. Por favor inicia sesión nuevamente.' 
            });
        } else {
            return res.status(401).json({ 
                success: false, 
                message: 'Error al verificar token. Por favor inicia sesión nuevamente.' 
            });
        }
    }
};

// Actualizar perfil
router.put('/actualizar-perfil', verifyToken, verifyCSRF, async (req, res) => {
    try {
        const { nombre, apellido, email, telefono } = req.body;
        
        // Verificar si el teléfono ya existe (si se está cambiando)
        if (telefono !== req.user.telefono) {
            const [existingUser] = await pool.query(
                'SELECT id_usuario FROM usuarios WHERE telefono = ? AND id_usuario != ?',
                [telefono, req.user.id_usuario]
            );
            
            if (existingUser.length > 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'El teléfono ya está registrado' 
                });
            }
        }
        
        // Actualizar usuario
        await pool.query(
            'UPDATE usuarios SET nombre = ?, apellido = ?, email = ?, telefono = ? WHERE id_usuario = ?',
            [nombre, apellido, email || null, telefono, req.user.id_usuario]
        );
        
        res.json({ 
            success: true, 
            message: 'Perfil actualizado exitosamente' 
        });
        
    } catch (error) {
        console.error('Error al actualizar perfil:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar perfil' 
        });
    }
});

// Cambiar contraseña
router.put('/cambiar-password', verifyToken, verifyCSRF, async (req, res) => {
    try {
        const { passwordActual, nuevaPassword } = req.body;
        
        // Obtener usuario actual
        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE id_usuario = ?',
            [req.user.id_usuario]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }
        
        const user = users[0];
        
        // Verificar contraseña actual
        const validPassword = await bcrypt.compare(passwordActual, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Contraseña actual incorrecta' 
            });
        }
        
        // Hashear nueva contraseña
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(nuevaPassword, salt);
        
        // Actualizar contraseña
        await pool.query(
            'UPDATE usuarios SET password_hash = ? WHERE id_usuario = ?',
            [password_hash, req.user.id_usuario]
        );
        
        res.json({ 
            success: true, 
            message: 'Contraseña cambiada exitosamente' 
        });
        
    } catch (error) {
        console.error('Error al cambiar contraseña:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al cambiar contraseña' 
        });
    }
});

// Login con MFA
router.post('/login-mfa', async (req, res) => {
    try {
        const { telefono, password, mfaToken } = req.body;

        // Validar campos
        if (!telefono || !password || !mfaToken) {
            return res.status(400).json({ 
                success: false, 
                message: 'Todos los campos son requeridos' 
            });
        }

        // Buscar usuario
        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE telefono = ? AND activo = TRUE',
            [telefono]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }

        const user = users[0];

        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }

        // Verificar MFA
        if (!user.mfa_enabled || !user.mfa_secret) {
            return res.status(400).json({ 
                success: false, 
                message: 'MFA no está habilitado' 
            });
        }

        // Descifrar secreto MFA
        const secret = decrypt(user.mfa_secret);

        // Verificar token TOTP
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: mfaToken
        });

        if (!verified) {
            return res.status(401).json({ 
                success: false, 
                message: 'Código MFA inválido' 
            });
        }

        // Descifrar email si existe
        const emailDescifrado = user.email ? decrypt(user.email) : null;

        // Generar token
        const token = jwt.sign(
            { 
                id_usuario: user.id_usuario, 
                telefono: user.telefono,
                rol: user.id_rol 
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Guardar sesión en base de datos
        const expiracion = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await pool.query(
            'INSERT INTO sesiones (id_usuario, token, expiracion) VALUES (?, ?, ?)',
            [user.id_usuario, token, expiracion]
        );

        // Enviar token en cookie segura
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000, // 24 horas
            path: '/'
        });

        // Enviar datos de usuario en respuesta
        res.json({ 
            success: true, 
            message: 'Login exitoso',
            user: {
                id_usuario: user.id_usuario,
                nombre: user.nombre,
                apellido: user.apellido,
                telefono: user.telefono,
                email: emailDescifrado,
                rol: user.id_rol
            }
        });

    } catch (error) {
        console.error('Error en login MFA:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al iniciar sesión' 
        });
    }
});

// Google OAuth2 - Iniciar autenticación
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth2 - Callback
router.get('/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    async (req, res) => {
        try {
            // Generar token JWT
            const token = jwt.sign(
                { 
                    id_usuario: req.user.id_usuario, 
                    telefono: req.user.telefono,
                    rol: req.user.id_rol 
                },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Guardar sesión en base de datos
            const expiracion = new Date(Date.now() + 24 * 60 * 60 * 1000);
            await pool.query(
                'INSERT INTO sesiones (id_usuario, token, expiracion) VALUES (?, ?, ?)',
                [req.user.id_usuario, token, expiracion]
            );

            // Enviar token en cookie segura
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000,
                path: '/'
            });

            // Obtener datos completos del usuario para sessionStorage
            const [users] = await pool.query(
                'SELECT id_usuario, nombre, apellido, telefono, email, id_rol FROM usuarios WHERE id_usuario = ?',
                [req.user.id_usuario]
            );

            const user = users[0];

            // Descifrar email si existe
            const emailDescifrado = user.email ? decrypt(user.email) : null;

            // Crear objeto de usuario para sessionStorage
            const userSession = {
                id_usuario: user.id_usuario,
                nombre: user.nombre,
                apellido: user.apellido,
                telefono: user.telefono,
                email: emailDescifrado,
                rol: user.id_rol
            };

            // Redirigir al dashboard con datos de usuario en cookie temporal
            res.cookie('userSession', JSON.stringify(userSession), {
                httpOnly: false,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 5000, // 5 segundos
                path: '/'
            });

            // Redirigir al dashboard
            res.redirect('/dashboard.html');
        } catch (error) {
            console.error('Error en callback de Google:', error);
            res.redirect('/login');
        }
    }
);

// MFA - Verificar estado
router.get('/mfa/status', verifyToken, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT mfa_enabled FROM usuarios WHERE id_usuario = ?',
            [req.user.id_usuario]
        );

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        res.json({
            success: true,
            mfa_enabled: users[0].mfa_enabled
        });

    } catch (error) {
        console.error('Error al verificar estado MFA:', error);
        res.status(500).json({ success: false, message: 'Error al verificar estado MFA' });
    }
});

// MFA - Generar secreto TOTP
router.post('/mfa/generate', verifyToken, verifyCSRF, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE id_usuario = ?',
            [req.user.id_usuario]
        );

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const user = users[0];

        // Generar secreto TOTP
        const secret = speakeasy.generateSecret({
            name: `Padel Online (${user.telefono})`,
            issuer: 'Padel Online'
        });

        // Generar QR Code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Guardar secreto cifrado en base de datos (temporal, no habilitado aún)
        const secretCifrado = encrypt(secret.base32);
        await pool.query(
            'UPDATE usuarios SET mfa_secret = ? WHERE id_usuario = ?',
            [secretCifrado, req.user.id_usuario]
        );

        res.json({
            success: true,
            secret: secret.base32,
            qrCode: qrCodeUrl
        });

    } catch (error) {
        console.error('Error al generar secreto MFA:', error);
        res.status(500).json({ success: false, message: 'Error al generar secreto MFA' });
    }
});

// MFA - Habilitar MFA
router.post('/mfa/enable', verifyToken, verifyCSRF, async (req, res) => {
    try {
        const { token: mfaToken } = req.body;

        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE id_usuario = ?',
            [req.user.id_usuario]
        );

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const user = users[0];

        if (!user.mfa_secret) {
            return res.status(400).json({ success: false, message: 'Primero genera un secreto MFA' });
        }

        // Descifrar secreto
        const secret = decrypt(user.mfa_secret);

        // Verificar token TOTP
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: mfaToken
        });

        if (!verified) {
            return res.status(401).json({ success: false, message: 'Código TOTP inválido' });
        }

        // Habilitar MFA
        await pool.query(
            'UPDATE usuarios SET mfa_enabled = TRUE WHERE id_usuario = ?',
            [req.user.id_usuario]
        );

        res.json({ success: true, message: 'MFA habilitado exitosamente' });

    } catch (error) {
        console.error('Error al habilitar MFA:', error);
        res.status(500).json({ success: false, message: 'Error al habilitar MFA' });
    }
});

// MFA - Verificar código TOTP
router.post('/mfa/verify', verifyToken, verifyCSRF, async (req, res) => {
    try {
        const { token: mfaToken } = req.body;

        const [users] = await pool.query(
            'SELECT * FROM usuarios WHERE id_usuario = ?',
            [req.user.id_usuario]
        );

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        const user = users[0];

        if (!user.mfa_enabled || !user.mfa_secret) {
            return res.status(400).json({ success: false, message: 'MFA no está habilitado' });
        }

        // Descifrar secreto
        const secret = decrypt(user.mfa_secret);

        // Verificar token TOTP
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: mfaToken
        });

        if (!verified) {
            return res.status(401).json({ success: false, message: 'Código TOTP inválido' });
        }

        res.json({ success: true, message: 'Código TOTP válido' });

    } catch (error) {
        console.error('Error al verificar MFA:', error);
        res.status(500).json({ success: false, message: 'Error al verificar MFA' });
    }
});

// MFA - Deshabilitar MFA
router.post('/mfa/disable', verifyToken, verifyCSRF, async (req, res) => {
    try {
        await pool.query(
            'UPDATE usuarios SET mfa_enabled = FALSE, mfa_secret = NULL WHERE id_usuario = ?',
            [req.user.id_usuario]
        );

        res.json({ success: true, message: 'MFA deshabilitado exitosamente' });

    } catch (error) {
        console.error('Error al deshabilitar MFA:', error);
        res.status(500).json({ success: false, message: 'Error al deshabilitar MFA' });
    }
});

module.exports = router;
