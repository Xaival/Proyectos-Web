<?php
// Clave de seguridad
$CLAVE_SECRETA = '1234';

// Cabecera de respuesta JSON
header('Content-Type: application/json');

// Leer y decodificar entrada
$raw = file_get_contents('php://input');
$in  = json_decode($raw, true);
if (!is_array($in)) {
    http_response_code(400);
    echo json_encode(['error' => 'JSON inválido']);
    exit;
}

// Verificar clave
if (!isset($in['clave']) || $in['clave'] !== $CLAVE_SECRETA) {
    http_response_code(403);
    echo json_encode(['error' => 'Clave incorrecta']);
    exit;
}

// Función de validación de cadenas libres de código malicioso
function esSeguro($str) {
    // No permitir etiquetas HTML ni opens de <script>
    if ($str !== strip_tags($str)) return false;
    // No permitir directivas JS en URLs
    if (preg_match('#\s*javascript:#i', $str)) return false;
    return true;
}

// Validar y sanear cada elemento
if (!isset($in['contenido']['destacado'], $in['contenido']['marcadores']) || !is_array($in['contenido']['destacado']) || !is_array($in['contenido']['marcadores'])) {
    http_response_code(422);
    echo json_encode(['error' => 'Estructura de contenido inválida']);
    exit;
}
foreach ($in['contenido']['destacado'] as $item) {
    if (!isset($item['name'], $item['url'], $item['img']) || !is_string($item['name']) || !is_string($item['url']) || !is_string($item['img']) || !esSeguro($item['name']) || !esSeguro($item['url']) || !esSeguro($item['img'])) {
        http_response_code(422);
        echo json_encode(['error' => 'Elemento destacado inválido o potencialmente peligroso']);
        exit;
    }
}
foreach ($in['contenido']['marcadores'] as $grupo) {
    if (!isset($grupo['grupo'], $grupo['marcadores']) || !is_string($grupo['grupo']) || !is_array($grupo['marcadores']) || !esSeguro($grupo['grupo'])) {
        http_response_code(422);
        echo json_encode(['error' => 'Grupo inválido o potencialmente peligroso']);
        exit;
    }
    foreach ($grupo['marcadores'] as $item) {
        if (!isset($item['name'], $item['url'], $item['img']) || !is_string($item['name']) || !is_string($item['url']) || !is_string($item['img']) || !esSeguro($item['name']) || !esSeguro($item['url']) || !esSeguro($item['img'])) {
            http_response_code(422);
            echo json_encode(['error' => "Marcador inválido o peligroso en grupo {$grupo['grupo']}"]);
            exit;
        }
    }
}

// Codificar contenido a JSON seguro para inyección en <script>
$json = json_encode($in['contenido'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_HEX_AMP | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT);

// Leer y sobrescribir index.html usando bloqueo exclusivo para evitar accesos concurrentes
$file = __DIR__ . '/index.html';
if (false === ($html = file_get_contents($file))) {
    http_response_code(500);
    echo json_encode(['error' => 'No se pudo leer index.html']);
    exit;
}

// Sustituir solo el primer <script id="marcadoresJSON">…</script>
$updated = preg_replace('#<script\s+id="marcadoresJSON">.*?</script>#s', "<script id=\"marcadoresJSON\">\nconst marcadoresJSON = $json;\n</script>", $html, 1);
if ($updated === null) {
    http_response_code(500);
    echo json_encode(['error' => 'Error al procesar HTML']);
    exit;
}

// Escritura segura
if (file_put_contents($file, $updated, LOCK_EX) === false) {
    http_response_code(500);
    echo json_encode(['error' => 'No se pudo guardar index.html']);
    exit;
}

// Respuesta de éxito
echo json_encode(['success' => true]);

?>
