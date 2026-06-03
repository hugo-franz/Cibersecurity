const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { encrypt, decrypt, hashData, verifyHash, sanitizeInput, signData, verifySignature } = require('../utils/security');
const { getPrivateKey, getPublicKey, canonicalReservaPayload } = require('../utils/keys');

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
const verifyToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Token no proporcionado' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Token inválido' });
    }
};

// Obtener reservas del usuario actual
router.get('/mis-reservas', verifyToken, async (req, res) => {
    try {
        const [reservas] = await pool.query(
            `SELECT r.*, c.nombre as nombre_cancha, c.precio_hora 
             FROM reservaciones r 
             INNER JOIN canchas c ON r.id_cancha = c.id_cancha 
             WHERE r.id_usuario = ? AND r.deleted_at IS NULL 
             ORDER BY r.fecha DESC, r.hora_inicio DESC`,
            [req.user.id_usuario]
        );

        // Verificar integridad de notas y firma digital
        const publicKey = getPublicKey();
        const reservasVerificadas = reservas.map(r => {
            // Verificar hash de notas (integridad)
            if (r.notas && r.notas_hash) {
                const hashValido = verifyHash(r.notas, r.notas_hash);
                if (!hashValido) {
                    console.warn('Hash de notas inválido para reserva:', r.id_reservacion);
                }
                r.notas_integridad_valida = hashValido;
            }

            // Verificar firma digital RSA (autenticidad e integridad de la reserva completa)
            if (r.firma_digital) {
                const payload = canonicalReservaPayload(r);
                const firmaValida = verifySignature(payload, r.firma_digital, publicKey);
                r.firma_valida = firmaValida;
                if (!firmaValida) {
                    console.warn('FIRMA DIGITAL INVÁLIDA para reserva:', r.id_reservacion,
                        '— posible manipulación de datos en BD.');
                }
            } else {
                r.firma_valida = null; // Reserva legacy sin firma
            }
            return r;
        });

        res.json({ success: true, reservas: reservasVerificadas });
    } catch (error) {
        console.error('Error al obtener reservas:', error);
        res.status(500).json({ success: false, message: 'Error al obtener reservas' });
    }
});

// Crear nueva reserva
router.post('/crear', verifyToken, verifyCSRF, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const { id_cancha, fecha, hora_inicio, duracion_minutos, notas } = req.body;

        // Validar campos
        if (!id_cancha || !fecha || !hora_inicio || !duracion_minutos) {
            return res.status(400).json({
                success: false,
                message: 'Todos los campos son requeridos'
            });
        }

        // Sanitizar notas si existen
        const notasSanitizadas = notas ? sanitizeInput(notas) : null;

        // Generar hash de notas para integridad
        const notasHash = notasSanitizadas ? hashData(notasSanitizadas) : null;

        // Verificar disponibilidad (consulta corregida: cálculo del hora_fin en SQL puro)
        const [existente] = await connection.query(
            `SELECT id_reservacion FROM reservaciones 
             WHERE id_cancha = ? AND fecha = ? AND estado != 'CANCELADA' 
             AND deleted_at IS NULL 
             AND (? < hora_fin AND ADDTIME(?, SEC_TO_TIME(? * 60)) > hora_inicio)`,
            [id_cancha, fecha, hora_inicio, hora_inicio, duracion_minutos]
        );

        if (existente.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'El horario ya está ocupado'
            });
        }

        // Iniciar transacción para crear + firmar de forma atómica
        await connection.beginTransaction();

        // Crear reserva
        const [result] = await connection.query(
            `INSERT INTO reservaciones 
             (id_usuario, id_cancha, fecha, hora_inicio, duracion_minutos, hora_fin, notas, notas_hash, estado) 
             VALUES (?, ?, ?, ?, ?, ADDTIME(?, SEC_TO_TIME(? * 60)), ?, ?, 'PENDIENTE_PAGO')`,
            [req.user.id_usuario, id_cancha, fecha, hora_inicio, duracion_minutos,
                hora_inicio, duracion_minutos, notasSanitizadas, notasHash]
        );

        const id_reservacion = result.insertId;

        // Generar firma digital RSA sobre los datos críticos de la reserva
        const payload = canonicalReservaPayload({
            id_reservacion,
            id_usuario: req.user.id_usuario,
            id_cancha,
            fecha,
            hora_inicio,
            duracion_minutos
        });
        const firma = signData(payload, getPrivateKey());

        // Guardar firma en la reserva recién creada
        await connection.query(
            'UPDATE reservaciones SET firma_digital = ? WHERE id_reservacion = ?',
            [firma, id_reservacion]
        );

        await connection.commit();

        res.json({
            success: true,
            message: 'Reserva creada y firmada digitalmente',
            id_reservacion,
            firma_digital: firma
        });

    } catch (error) {
        await connection.rollback();
        console.error('Error al crear reserva:', error);
        res.status(500).json({ success: false, message: 'Error al crear reserva' });
    } finally {
        connection.release();
    }
});

// Cancelar reserva
router.put('/cancelar/:id', verifyToken, verifyCSRF, async (req, res) => {
    try {
        const id_reservacion = req.params.id;

        // Validar que el ID sea numérico (defensa en profundidad anti-SQLi)
        if (!/^\d+$/.test(id_reservacion)) {
            return res.status(400).json({ success: false, message: 'ID inválido' });
        }

        // Verificar que la reserva pertenezca al usuario
        const [reserva] = await pool.query(
            'SELECT * FROM reservaciones WHERE id_reservacion = ? AND id_usuario = ?',
            [id_reservacion, req.user.id_usuario]
        );

        if (reserva.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Reserva no encontrada'
            });
        }

        // Cancelar reserva
        await pool.query(
            `UPDATE reservaciones 
             SET estado = 'CANCELADA', fecha_cancelacion = NOW(), cancelada_por = ? 
             WHERE id_reservacion = ?`,
            [req.user.id_usuario, id_reservacion]
        );

        res.json({ success: true, message: 'Reserva cancelada exitosamente' });

    } catch (error) {
        console.error('Error al cancelar reserva:', error);
        res.status(500).json({ success: false, message: 'Error al cancelar reserva' });
    }
});

// Endpoint para que un cliente verifique manualmente una reserva contra su firma
router.get('/verificar/:id', verifyToken, async (req, res) => {
    try {
        const id_reservacion = req.params.id;

        if (!/^\d+$/.test(id_reservacion)) {
            return res.status(400).json({ success: false, message: 'ID inválido' });
        }

        const [reservas] = await pool.query(
            'SELECT * FROM reservaciones WHERE id_reservacion = ? AND id_usuario = ?',
            [id_reservacion, req.user.id_usuario]
        );

        if (reservas.length === 0) {
            return res.status(404).json({ success: false, message: 'Reserva no encontrada' });
        }

        const r = reservas[0];

        if (!r.firma_digital) {
            return res.json({
                success: true,
                firmada: false,
                message: 'Esta reserva no tiene firma digital (reserva anterior a esta funcionalidad)'
            });
        }

        const payload = canonicalReservaPayload(r);
        const valida = verifySignature(payload, r.firma_digital, getPublicKey());

        res.json({
            success: true,
            firmada: true,
            firma_valida: valida,
            payload_firmado: payload,
            message: valida
                ? 'La firma es válida — los datos no han sido alterados.'
                : 'ADVERTENCIA: La firma NO es válida. Los datos pueden haber sido manipulados.'
        });

    } catch (error) {
        console.error('Error al verificar firma:', error);
        res.status(500).json({ success: false, message: 'Error al verificar firma' });
    }
});

// Middleware para verificar que sea administrador
const verifyAdmin = (req, res, next) => {
    if (req.user.rol !== 1) {
        return res.status(403).json({ success: false, message: 'Acceso denegado. Solo administradores.' });
    }
    next();
};

// Obtener todas las reservaciones (solo admin)
router.get('/todas', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const [reservas] = await pool.query(
            `SELECT r.*, c.nombre as nombre_cancha, c.precio_hora, 
                    u.nombre as nombre_usuario, u.apellido as apellido_usuario, u.telefono as telefono_usuario
             FROM reservaciones r 
             INNER JOIN canchas c ON r.id_cancha = c.id_cancha 
             INNER JOIN usuarios u ON r.id_usuario = u.id_usuario
             WHERE r.deleted_at IS NULL 
             ORDER BY r.fecha DESC, r.hora_inicio DESC`
        );

        res.json({ success: true, reservas });
    } catch (error) {
        console.error('Error al obtener todas las reservas:', error);
        res.status(500).json({ success: false, message: 'Error al obtener reservas' });
    }
});

// Obtener estadísticas de ventas (solo admin)
router.get('/estadisticas', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const periodo = req.query.periodo || 'hoy';

        let fechaInicio;
        const hoy = new Date();

        switch (periodo) {
            case 'hoy':
                fechaInicio = new Date(hoy.setHours(0, 0, 0, 0));
                break;
            case 'semana':
                fechaInicio = new Date(hoy.setDate(hoy.getDate() - 7));
                break;
            case 'mes':
                fechaInicio = new Date(hoy.setDate(hoy.getDate() - 30));
                break;
            default:
                fechaInicio = new Date(hoy.setHours(0, 0, 0, 0));
        }

        const [ventas] = await pool.query(
            `SELECT r.*, c.nombre as nombre_cancha, c.precio_hora,
                    u.nombre as nombre_usuario, u.apellido as apellido_usuario, u.telefono as telefono_usuario
             FROM reservaciones r 
             INNER JOIN canchas c ON r.id_cancha = c.id_cancha 
             INNER JOIN usuarios u ON r.id_usuario = u.id_usuario
             WHERE r.fecha >= ? AND r.estado != 'CANCELADA' AND r.deleted_at IS NULL
             ORDER BY r.fecha DESC, r.hora_inicio DESC`,
            [fechaInicio.toISOString().split('T')[0]]
        );

        const totalVentas = ventas.reduce((sum, r) => sum + (r.duracion_minutos / 60 * r.precio_hora), 0);
        const totalReservas = ventas.length;
        const canchasMasUsadas = {};

        ventas.forEach(r => {
            canchasMasUsadas[r.nombre_cancha] = (canchasMasUsadas[r.nombre_cancha] || 0) + 1;
        });

        res.json({
            success: true,
            ventas,
            estadisticas: { totalVentas, totalReservas, canchasMasUsadas }
        });
    } catch (error) {
        console.error('Error al obtener estadísticas:', error);
        res.status(500).json({ success: false, message: 'Error al obtener estadísticas' });
    }
});

// Dashboard admin (igual que antes, no se toca para mantener el commit enfocado)
router.get('/dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const hoy = new Date().toISOString().split('T')[0];
        const hace7dias = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        const hace30dias = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

        const [ventasHoy] = await pool.query(
            `SELECT SUM(r.duracion_minutos / 60 * c.precio_hora) as total, COUNT(*) as cantidad
             FROM reservaciones r 
             INNER JOIN canchas c ON r.id_cancha = c.id_cancha 
             WHERE r.fecha = ? AND r.estado != 'CANCELADA' AND r.deleted_at IS NULL`,
            [hoy]
        );

        const [ventasSemana] = await pool.query(
            `SELECT SUM(r.duracion_minutos / 60 * c.precio_hora) as total, COUNT(*) as cantidad
             FROM reservaciones r 
             INNER JOIN canchas c ON r.id_cancha = c.id_cancha 
             WHERE r.fecha >= ? AND r.estado != 'CANCELADA' AND r.deleted_at IS NULL`,
            [hace7dias]
        );

        const [ventasMes] = await pool.query(
            `SELECT SUM(r.duracion_minutos / 60 * c.precio_hora) as total, COUNT(*) as cantidad
             FROM reservaciones r 
             INNER JOIN canchas c ON r.id_cancha = c.id_cancha 
             WHERE r.fecha >= ? AND r.estado != 'CANCELADA' AND r.deleted_at IS NULL`,
            [hace30dias]
        );

        const [reservasPorEstado] = await pool.query(
            `SELECT estado, COUNT(*) as cantidad FROM reservaciones 
             WHERE deleted_at IS NULL GROUP BY estado`
        );

        const [canchasTop] = await pool.query(
            `SELECT c.nombre, COUNT(r.id_reservacion) as total_reservas
             FROM canchas c
             LEFT JOIN reservaciones r ON c.id_cancha = r.id_cancha AND r.deleted_at IS NULL
             GROUP BY c.id_cancha, c.nombre
             ORDER BY total_reservas DESC LIMIT 5`
        );

        res.json({
            success: true,
            dashboard: {
                hoy: ventasHoy[0],
                semana: ventasSemana[0],
                mes: ventasMes[0],
                porEstado: reservasPorEstado,
                canchasTop
            }
        });
    } catch (error) {
        console.error('Error al obtener dashboard:', error);
        res.status(500).json({ success: false, message: 'Error al obtener dashboard' });
    }
});

module.exports = router;
