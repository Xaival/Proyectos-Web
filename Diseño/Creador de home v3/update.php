<?php
// Clave de seguridad
$CLAVE_SECRETA = '1234';

// Establecer cabecera de respuesta JSON
header('Content-Type: application/json');

// Leer entrada
$rawData = file_get_contents('php://input');
$data = json_decode($rawData, true);

// Verificar clave
if (!isset($data['clave']) || $data['clave'] !== $CLAVE_SECRETA) {
    http_response_code(403);
    echo json_encode(['error' => 'Clave incorrecta']);
    exit;
}

// Codificar contenido
$json = json_encode($data['contenido'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

// Leer index.html
$html = file_get_contents('index.html');

// Reemplazar contenido del <script id="marcadoresJSON">
$html = preg_replace(
    '#<script id="marcadoresJSON">.*?</script>#s',
    "<script id=\"marcadoresJSON\">\nconst marcadoresJSON = $json;\n</script>",
    $html
);

// Guardar cambios en index.html
file_put_contents('index.html', $html);

// Respuesta
echo json_encode(['success' => true]);

?>
