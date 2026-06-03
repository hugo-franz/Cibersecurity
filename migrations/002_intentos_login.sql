-- Migración 002: Tabla para auditoría de intentos de login (exitosos y fallidos).
-- Complementa al rate limiter en memoria persistiendo evidencia forense.

CREATE TABLE IF NOT EXISTS intentos_login (
    id_intento INT AUTO_INCREMENT PRIMARY KEY,
    telefono VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,  -- IPv4 o IPv6
    user_agent VARCHAR(500) NULL,
    exitoso BOOLEAN NOT NULL DEFAULT FALSE,
    razon_fallo VARCHAR(100) NULL,  -- 'usuario_no_existe', 'password_incorrecto', 'mfa_invalido', etc.
    fecha_intento TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_telefono_fecha (telefono, fecha_intento),
    INDEX idx_ip_fecha (ip_address, fecha_intento)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Vista útil para revisar intentos fallidos recientes
CREATE OR REPLACE VIEW v_intentos_fallidos_recientes AS
SELECT
    telefono,
    ip_address,
    razon_fallo,
    COUNT(*) AS intentos,
    MAX(fecha_intento) AS ultimo_intento
FROM intentos_login
WHERE exitoso = FALSE
  AND fecha_intento > DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY telefono, ip_address, razon_fallo
ORDER BY intentos DESC, ultimo_intento DESC;
