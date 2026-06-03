const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const { verifyToken, verifyCSRF, verifyAdmin, validateNumericParam } = require('../middleware/auth');
const { sanitizeInput } = require('../utils/security');

// Obtener todas las canchas activas
router.get('/', async (req, res) => {
    try {
        const [canchas] = await pool.query(
            'SELECT * FROM canchas WHERE activa = TRUE ORDER BY nombre'
        );
        res.json({ success: true, canchas });
    } catch (error) {
        console.error('Error al obtener canchas:', error);
        res.status(500).json({ success: false, message: 'Error al obtener canchas' });
    }
});

// Obtener una cancha específica (con validación de ID)
router.get('/:id', validateNumericParam('id'), async (req, res) => {
    try {
        const [canchas] = await pool.query(
            'SELECT * FROM canchas WHERE id_cancha = ? AND activa = TRUE',
            [req.params.id]
        );

        if (canchas.length === 0) {
            return res.status(404).json({ success: false, message: 'Cancha no encontrada' });
        }

        const [imagenes] = await pool.query(
            'SELECT * FROM imagenes_cancha WHERE id_cancha = ?',
            [req.params.id]
        );

        const [disponibilidad] = await pool.query(
            'SELECT * FROM disponibilidad_cancha WHERE id_cancha = ?',
            [req.params.id]
        );

        res.json({
            success: true,
            cancha: canchas[0],
            imagenes,
            disponibilidad
        });
    } catch (error) {
        console.error('Error al obtener cancha:', error);
        res.status(500).json({ success: false, message: 'Error al obtener cancha' });
    }
});

// Obtener disponibilidad de una cancha en una fecha (valida ID y formato fecha)
router.get('/:id/disponibilidad/:fecha', validateNumericParam('id'), async (req, res) => {
    try {
        const { id, fecha } = req.params;

        // Validar formato de fecha YYYY-MM-DD (defensa en profundidad)
        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({
                success: false,
                message: 'Formato de fecha inválido (esperado YYYY-MM-DD)'
            });
        }

        const [ocupados] = await pool.query(
            `SELECT hora_inicio, hora_fin 
             FROM reservaciones 
             WHERE id_cancha = ? AND fecha = ? AND estado != 'CANCELADA' 
             AND deleted_at IS NULL 
             ORDER BY hora_inicio`,
            [id, fecha]
        );

        const [disponibilidad] = await pool.query(
            'SELECT * FROM disponibilidad_cancha WHERE id_cancha = ?',
            [id]
        );

        res.json({ success: true, horarios_ocupados: ocupados, disponibilidad });
    } catch (error) {
        console.error('Error al obtener disponibilidad:', error);
        res.status(500).json({ success: false, message: 'Error al obtener disponibilidad' });
    }
});

// ENDPOINTS ADMIN — crear, actualizar, desactivar canchas
// Aplican verifyToken (con check de sesión en BD) + verifyCSRF + verifyAdmin

router.post('/', verifyToken, verifyCSRF, verifyAdmin, async (req, res) => {
    try {
        const { nombre, descripcion, precio_hora, tipo } = req.body;

        if (!nombre || !precio_hora) {
            return res.status(400).json({
                success: false,
                message: 'Nombre y precio por hora son requeridos'
            });
        }

        if (isNaN(parseFloat(precio_hora)) || parseFloat(precio_hora) < 0) {
            return res.status(400).json({
                success: false,
                message: 'El precio debe ser un número positivo'
            });
        }

        const nombreSan = sanitizeInput(nombre);
        const descSan = descripcion ? sanitizeInput(descripcion) : null;
        const tipoSan = tipo ? sanitizeInput(tipo) : null;

        const [result] = await pool.query(
            'INSERT INTO canchas (nombre, descripcion, precio_hora, tipo, activa) VALUES (?, ?, ?, ?, TRUE)',
            [nombreSan, descSan, parseFloat(precio_hora), tipoSan]
        );

        res.status(201).json({
            success: true,
            message: 'Cancha creada exitosamente',
            id_cancha: result.insertId
        });
    } catch (error) {
        console.error('Error al crear cancha:', error);
        res.status(500).json({ success: false, message: 'Error al crear cancha' });
    }
});

router.put('/:id', validateNumericParam('id'), verifyToken, verifyCSRF, verifyAdmin, async (req, res) => {
    try {
        const { nombre, descripcion, precio_hora, tipo, activa } = req.body;
        const nombreSan = nombre ? sanitizeInput(nombre) : null;
        const descSan = descripcion ? sanitizeInput(descripcion) : null;
        const tipoSan = tipo ? sanitizeInput(tipo) : null;

        await pool.query(
            `UPDATE canchas 
             SET nombre = COALESCE(?, nombre),
                 descripcion = COALESCE(?, descripcion),
                 precio_hora = COALESCE(?, precio_hora),
                 tipo = COALESCE(?, tipo),
                 activa = COALESCE(?, activa)
             WHERE id_cancha = ?`,
            [nombreSan, descSan, precio_hora, tipoSan, activa, req.params.id]
        );

        res.json({ success: true, message: 'Cancha actualizada' });
    } catch (error) {
        console.error('Error al actualizar cancha:', error);
        res.status(500).json({ success: false, message: 'Error al actualizar cancha' });
    }
});

router.delete('/:id', validateNumericParam('id'), verifyToken, verifyCSRF, verifyAdmin, async (req, res) => {
    try {
        await pool.query(
            'UPDATE canchas SET activa = FALSE WHERE id_cancha = ?',
            [req.params.id]
        );
        res.json({ success: true, message: 'Cancha desactivada' });
    } catch (error) {
        console.error('Error al desactivar cancha:', error);
        res.status(500).json({ success: false, message: 'Error al desactivar cancha' });
    }
});

module.exports = router;
