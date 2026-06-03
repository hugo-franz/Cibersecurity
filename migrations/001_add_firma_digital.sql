-- Migración 001: Agregar columna para firma digital RSA en reservaciones.
-- La firma se genera en el momento de crear la reserva con la clave privada del servidor
-- y se verifica al consultarla, garantizando que no fue alterada en BD.

ALTER TABLE reservaciones
    ADD COLUMN firma_digital VARCHAR(1024) NULL
    AFTER notas_hash;

-- Índice opcional si se va a consultar por integridad masivamente
-- CREATE INDEX idx_firma_digital ON reservaciones(firma_digital(64));
