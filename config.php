<?php
// Fungsi untuk mem-parsing file .env
function loadEnv($path) {
    if (!file_exists($path)) {
        throw new Exception("File .env tidak ditemukan di path: {$path}");
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);

        if (substr($value, 0, 1) == '"' && substr($value, -1) == '"') {
            $value = substr($value, 1, -1);
        }

        putenv(sprintf('%s=%s', $name, $value));
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

// --- PERUBAHAN DI SINI ---
// Muat file .env dari direktori root (satu tingkat di atas direktori saat ini)
try {
    loadEnv(__DIR__ . '/../.env'); // Ditambahkan '/..' untuk naik satu direktori
} catch (Exception $e) {
    header("Content-Type: application/json");
    http_response_code(500);
    echo json_encode(["error" => "Konfigurasi server bermasalah: " . $e->getMessage()]);
    exit();
}

// Definisikan kredensial database dari variabel environment
$db_host = getenv('DB_HOST');
$db_user = getenv('DB_USERNAME');
$db_pass = getenv('DB_PASSWORD');
$db_name = getenv('DB_NAME');
?>