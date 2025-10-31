<?php
// Aktifkan pelaporan error untuk debugging (HAPUS ATAU KOMENTARI DI PRODUKSI)
// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);
ini_set('log_errors', 1); // Aktifkan logging ke file
ini_set('error_log', 'php_error.log'); // Tentukan nama file log

header("Content-Type: application/json");
require_once 'config.php'; // Memuat konfigurasi DB

// --- Tambahkan ini jika Anda menggunakan Composer ---
require_once 'vendor/autoload.php';
// ---------------------------------------------

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use \Firebase\JWT\ExpiredException;

// --- GANTI DENGAN FIREBASE PROJECT ID ANDA ---
const FIREBASE_PROJECT_ID = 'kamus-korea-apps-dcf09';
// ---------------------------------------------

// --- Cache untuk Google Public Keys (opsional tapi disarankan) ---
const PUBLIC_KEY_CACHE_FILE = 'google_public_keys.json';
const PUBLIC_KEY_CACHE_EXPIRY = 3600; // 1 jam

// Koneksi Database
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    error_log("Koneksi database gagal: " . $conn->connect_error); // Log error
    http_response_code(500);
    echo json_encode(["error" => "Koneksi database gagal."]); // Pesan generik ke user
    exit();
}
$conn->set_charset("utf8mb4");

// Ambil User ID dari Firebase Token
$userId = getUserIdFromToken(); // Fungsi ini akan memverifikasi token

// --- Routing Sederhana ---
$requestMethod = $_SERVER['REQUEST_METHOD'];
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$pathSegments = explode('/', trim($requestUri, '/'));

$basePathSegments = ['kamuskorea']; // Ubah jika base path Anda berbeda
$apiPathSegments = array_slice($pathSegments, count($basePathSegments));

$apiStartIndex = 0;
if (isset($apiPathSegments[0]) && ($apiPathSegments[0] == 'api.php' || $apiPathSegments[0] == 'api')) {
    $apiStartIndex = 1;
}
$endpointPath = array_slice($apiPathSegments, $apiStartIndex);


if (isset($endpointPath[0])) {
    switch ($endpointPath[0]) {
        case 'kamus':
            if ($requestMethod == 'GET' && isset($endpointPath[1]) && $endpointPath[1] == 'updates') {
                handleKamusUpdates($conn);
            } else {
                notFound();
            }
            break;

        case 'user':
            if (!$userId) { unauthorized("User ID tidak ditemukan dari token."); break; } // Endpoint 'user' butuh autentikasi valid
            ensureUserExists($conn, $userId); // Pastikan user ada

            if (isset($endpointPath[1])) {
                switch ($endpointPath[1]) {
                    case 'premium':
                        if ($requestMethod == 'GET' && isset($endpointPath[2]) && $endpointPath[2] == 'status') {
                            handlePremiumStatus($conn, $userId);
                        } else {
                            notFound();
                        }
                        break;
                    case 'profile':
                        if ($requestMethod == 'GET') {
                             handleGetUserProfile($conn, $userId);
                        }
                        elseif ($requestMethod == 'PATCH') { // Update Nama & DOB
                            handleProfileUpdate($conn, $userId);
                        } elseif ($requestMethod == 'POST' && isset($endpointPath[2]) && $endpointPath[2] == 'picture') { // Update Foto
                            handleProfilePictureUpload($conn, $userId);
                        } else {
                            notFound();
                        }
                        break;
                    default:
                        notFound();
                }
            } else {
                 // Jika hanya /user (GET), kembalikan profil
                 if ($requestMethod == 'GET') {
                    handleGetUserProfile($conn, $userId);
                 } else {
                    notFound();
                 }
            }
            break;

        case 'ebooks':
            if ($requestMethod == 'GET') {
                handleGetEbooks($conn, $userId); // userId bisa null jika user belum login
            } else {
                notFound();
            }
            break;

        default:
            notFound();
    }
} else {
    echo json_encode(["message" => "Selamat datang di API Kamus Korea"]);
}

$conn->close();

// --- Fungsi Helper ---

function getGooglePublicKeys() {
    $cacheFile = PUBLIC_KEY_CACHE_FILE;
    $cacheExpiry = PUBLIC_KEY_CACHE_EXPIRY;

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheExpiry) {
        $keysJson = file_get_contents($cacheFile);
    } else {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        // curl_setopt($ch, CURLOPT_CAINFO, '/path/to/cacert.pem'); // Jika perlu CA bundle
        $keysJson = curl_exec($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($keysJson === false || $httpcode !== 200) {
             error_log("Gagal mengambil Google Public Keys. HTTP Code: {$httpcode}. cURL Error: {$curlError}");
             // Coba baca cache lama jika ada, meskipun sudah expired
             if (file_exists($cacheFile)) {
                 error_log("Menggunakan cache Google Public Keys yang mungkin sudah kedaluwarsa.");
                 $keysJson = file_get_contents($cacheFile);
             } else {
                throw new Exception("Gagal mengambil Google Public Keys dan tidak ada cache.");
             }
        } else {
             // Simpan cache baru jika berhasil
             file_put_contents($cacheFile, $keysJson);
        }
    }
    $decodedKeys = json_decode($keysJson, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("Gagal decode JSON Google Public Keys: " . json_last_error_msg());
        throw new Exception("Gagal decode JSON Google Public Keys.");
    }
    return $decodedKeys;
}


function getUserIdFromToken() {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
    if (!$authHeader) {
        error_log("getUserIdFromToken: Header Authorization tidak ditemukan."); // Log 1
        return null;
    }

    if (strpos($authHeader, 'Bearer ') !== 0) {
        error_log("getUserIdFromToken: Format header Authorization salah."); // Log 2
        return null;
    }

    $token = trim(substr($authHeader, 7));
    if (empty($token)) {
        error_log("getUserIdFromToken: Token Bearer kosong."); // Log 3
        return null;
    }

    // error_log("getUserIdFromToken: Menerima token: " . substr($token, 0, 20) . "..."); // Log 4

    try {
        error_log("getUserIdFromToken: Mencoba mengambil Google Public Keys..."); // Log 5
        $publicKeys = getGooglePublicKeys();
        if (!$publicKeys) {
             error_log("getUserIdFromToken: Gagal mendapatkan Google Public Keys."); // Log 6
             return null;
        }
        error_log("getUserIdFromToken: Google Public Keys berhasil didapatkan."); // Log 7

        // Decode header untuk mendapatkan kid
        $tks = explode('.', $token);
        if (count($tks) != 3) {
            error_log("getUserIdFromToken: Format token JWT tidak valid (bukan 3 bagian)."); // Log 8
            return null;
        }
        list($headb64, $bodyb64, $sigb64) = $tks;
        $headerRaw = JWT::urlsafeB64Decode($headb64);
        if (!$headerRaw) { error_log("getUserIdFromToken: Gagal decode base64 header token."); return null; } // Log 9
        $header = JWT::jsonDecode($headerRaw);
        if (!$header) { error_log("getUserIdFromToken: Gagal decode JSON header token."); return null; } // Log 10
        $kid = $header->kid ?? null;
        error_log("getUserIdFromToken: Token KID: " . ($kid ?? 'NULL')); // Log 11

        if (!$kid || !isset($publicKeys[$kid])) {
            error_log("getUserIdFromToken: Token KID '$kid' tidak ditemukan di Google Public Keys."); // Log 12
            // error_log("getUserIdFromToken: Public keys tersedia: " . implode(', ', array_keys($publicKeys)));
            return null;
        }
        $publicKey = $publicKeys[$kid];
        error_log("getUserIdFromToken: Public key ditemukan untuk KID '$kid'."); // Log 13


        // Set leeway
        $leeway = 60;
        JWT::$leeway = $leeway;
        error_log("getUserIdFromToken: Leeway diatur ke {$leeway} detik."); // Log 14

        // Decode dan verifikasi token
        error_log("getUserIdFromToken: Mencoba decode token..."); // Log 15
        $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));
        error_log("getUserIdFromToken: Token berhasil di-decode."); // Log 16

        // Reset leeway
        JWT::$leeway = 0;

        // Cek issuer dan audience
        $projectId = FIREBASE_PROJECT_ID;
        $expectedIss = 'https://securetoken.google.com/' . $projectId;
        $expectedAud = $projectId;

        error_log("getUserIdFromToken: Memeriksa issuer. Expected='{$expectedIss}', Actual='{$decoded->iss}'"); // Log 17
        error_log("getUserIdFromToken: Memeriksa audience. Expected='{$expectedAud}', Actual='{$decoded->aud}'"); // Log 18

        if ($decoded->iss !== $expectedIss || $decoded->aud !== $expectedAud) {
            error_log("getUserIdFromToken: Issuer atau Audience token TIDAK COCOK."); // Log 19
            return null;
        }

        error_log("getUserIdFromToken: Issuer dan Audience COCOK."); // Log 20
        error_log("getUserIdFromToken: Verifikasi BERHASIL. User ID: {$decoded->sub}"); // Log 21
        return $decoded->sub; // Kembalikan Firebase UID

    } catch (ExpiredException $e) {
        error_log("getUserIdFromToken: Token kedaluwarsa: " . $e->getMessage()); // Log 22
        return null; // Token expired
    } catch (Exception $e) {
        // Tangkap semua jenis exception lain
        error_log("getUserIdFromToken: Error verifikasi token JWT atau pengambilan keys: " . $e->getMessage()); // Log 23
        return null;
    }
}

// Fungsi untuk memastikan user ada di DB
function ensureUserExists($conn, $userId) {
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE firebase_uid = ?");
    if (!$stmt) { /* Log error */ return; }
    $stmt->bind_param("s", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $count = $result->fetch_row()[0];
    $stmt->close();

    if ($count == 0) {
        $insertStmt = $conn->prepare("INSERT INTO users (firebase_uid, created_at, updated_at) VALUES (?, NOW(), NOW())"); // Tambah timestamp
         if (!$insertStmt) { /* Log error */ return; }
        $insertStmt->bind_param("s", $userId);
        $insertStmt->execute();
        if ($insertStmt->affected_rows > 0) {
             error_log("User baru ditambahkan ke DB: " . $userId);
        } else {
             error_log("Gagal menambahkan user baru ke DB: " . $userId . " Error: " . $insertStmt->error);
        }
        $insertStmt->close();
    }
}


function handleGetEbooks($conn, $userId) {
    $isPremiumUser = false;
    if ($userId) {
        $isPremiumUser = checkUserPremiumStatus($conn, $userId);
    }

    $sql = "
        SELECT
            id, title, description, coverImageUrl, `order`, isPremium,
            CASE
                WHEN isPremium = 1 AND ? = 0 THEN ''
                ELSE pdfUrl
            END AS pdfUrl
        FROM ebooks ORDER BY `order` ASC
    ";

    $stmt = $conn->prepare($sql);
    $isPremiumInt = $isPremiumUser ? 1 : 0;
    $stmt->bind_param("i", $isPremiumInt);
    $stmt->execute();
    $result = $stmt->get_result();
    $ebooks = [];

    if ($result) {
        while($row = $result->fetch_assoc()) {
            $row['isPremium'] = (bool)$row['isPremium'];
            if ($row['coverImageUrl'] && !preg_match("~^(?:f|ht)tps?://~i", $row['coverImageUrl'])) {
                 $row['coverImageUrl'] = "https://webtechsolution.my.id/kamuskorea/" . ltrim($row['coverImageUrl'], '/'); // Ubah http ke https jika server mendukung
            }
            if ($row['pdfUrl'] && !preg_match("~^(?:f|ht)tps?://~i", $row['pdfUrl'])) {
                 $row['pdfUrl'] = "https://webtechsolution.my.id/kamuskorea/" . ltrim($row['pdfUrl'], '/'); // Ubah http ke https jika server mendukung
            }
            $ebooks[] = $row;
        }
    } else {
        error_log("Error query ebooks: " . $conn->error);
        http_response_code(500);
        echo json_encode(["error" => "Gagal mengambil data ebook."]);
        return;
    }
    echo json_encode($ebooks);
    $stmt->close();
}

function handleKamusUpdates($conn) {
    $localVersion = isset($_GET['version']) ? intval($_GET['version']) : 0;
    
    // --- SESUAIKAN IMPLEMENTASI SQL INI ---
    $currentDbVersion = 0;
    // Contoh 1: Jika punya tabel 'kamus_meta' dengan kolom 'versi'
    // $versionResult = $conn->query("SELECT versi FROM kamus_meta ORDER BY id DESC LIMIT 1");
    // Contoh 2: Jika versi disimpan di tempat lain
    // $currentDbVersion = ambilVersiDariSumberLain();
    
    // Placeholder - Asumsikan versi 1 adalah terbaru
    $currentDbVersion = 1;

    $words = [];
    if ($localVersion < $currentDbVersion) {
        // CONTOH SQL: Ambil semua kata jika versi 0, atau yang berubah (sesuaikan!)
        // Asumsi tabel `words` punya kolom `id`, `korean_word`, `romanization`, `indonesian_translation`
        $sql = "SELECT id, korean_word as korean, romanization, indonesian_translation as indonesian FROM words"; 
        // Tambahkan WHERE clause jika perlu (misal: `WHERE version_added > ?` atau `WHERE updated_at > ?`)

        $stmt = $conn->prepare($sql);
        if (!$stmt) {
             error_log("Prepare statement gagal (handleKamusUpdates): " . $conn->error);
             http_response_code(500);
             echo json_encode(["latestVersion" => $localVersion, "words" => [], "error" => "Gagal menyiapkan query kamus."]);
             return;
        }
        // Jika pakai WHERE: $stmt->bind_param("i", $localVersion);
        
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result) {
            while($row = $result->fetch_assoc()) {
                $words[] = $row;
            }
        } else {
             error_log("Gagal query kata-kata kamus: " . $stmt->error);
             // Kirim response error tapi mungkin tetap dengan versi terbaru agar klien tidak terus mencoba
             http_response_code(500);
             echo json_encode(["latestVersion" => $currentDbVersion, "words" => [], "error" => "Gagal mengambil data kamus."]);
             $stmt->close();
             return;
        }
        $stmt->close();
    }

    $response = [
        "latestVersion" => $currentDbVersion,
        "words" => $words
    ];
    echo json_encode($response);
}

function handlePremiumStatus($conn, $userId) {
    $isPremium = checkUserPremiumStatus($conn, $userId, true); // true = cek expiry
    $expiryDate = null;

    $stmt = $conn->prepare("SELECT expiryDate FROM users WHERE firebase_uid = ?");
    if (!$stmt) { /* Log error */ } else {
        $stmt->bind_param("s", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result && $row = $result->fetch_assoc()) {
            $expiryDate = $row['expiryDate'];
        }
        $stmt->close();
    }

    echo json_encode(["isPremium" => $isPremium, "expiryDate" => $expiryDate]);
}

function checkUserPremiumStatus($conn, $userId, $checkExpiry = false) {
    $stmt = $conn->prepare("SELECT isPremium, expiryDate FROM users WHERE firebase_uid = ? LIMIT 1");
    if (!$stmt) {
        error_log("Prepare statement gagal (checkUserPremiumStatus - SELECT): " . $conn->error);
        return false;
    }
    $stmt->bind_param("s", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $row = $result->fetch_assoc()) {
        $isPremium = (bool)$row['isPremium'];
        $expiryDate = $row['expiryDate'];
        $stmt->close();

        if ($checkExpiry && $isPremium && $expiryDate) {
            try {
                $today = new DateTime();
                $expiry = new DateTime($expiryDate);
                $today->setTime(0, 0, 0);
                $expiry->setTime(0, 0, 0);

                if ($today > $expiry) {
                    $updateStmt = $conn->prepare("UPDATE users SET isPremium = FALSE WHERE firebase_uid = ?");
                    if (!$updateStmt) {
                        error_log("Prepare statement gagal (checkUserPremiumStatus - UPDATE): " . $conn->error);
                        return false;
                    }
                    $updateStmt->bind_param("s", $userId);
                    $updateSuccess = $updateStmt->execute();
                    $updateStmt->close();
                    if ($updateSuccess) {
                        error_log("Status premium user {$userId} diubah menjadi FALSE karena kedaluwarsa.");
                        return false;
                    } else {
                         error_log("Gagal update status premium menjadi FALSE untuk user {$userId}.");
                         return false;
                    }
                }
            } catch (Exception $e) {
                error_log("Error membandingkan tanggal expiry untuk user {$userId}: " . $e->getMessage());
                 return false;
            }
        }
        return $isPremium;
    } else {
         if ($stmt->error) { error_log("Error eksekusi checkUserPremiumStatus - SELECT: " . $stmt->error); }
         $stmt->close();
         return false;
    }
}

function handleGetUserProfile($conn, $userId) {
    $stmt = $conn->prepare("SELECT name, dob, profile_picture_url FROM users WHERE firebase_uid = ?");
    if (!$stmt) {
        error_log("Prepare statement gagal (handleGetUserProfile): " . $conn->error);
        http_response_code(500);
        echo json_encode(["error" => "Gagal mengambil data profil."]);
        return;
    }
    $stmt->bind_param("s", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $profileData = $result->fetch_assoc()) {
        echo json_encode([
            "name" => $profileData['name'],
            "dob" => $profileData['dob'],
            "profilePictureUrl" => $profileData['profile_picture_url']
        ]);
    } else {
        if ($stmt->error) {
             error_log("Error fetch profil user {$userId}: " . $stmt->error);
             http_response_code(500);
             echo json_encode(["error" => "Gagal mengambil data profil."]);
        } else {
             echo json_encode([ "name" => null, "dob" => null, "profilePictureUrl" => null ]);
        }
    }
    $stmt->close();
}


function handleProfileUpdate($conn, $userId) {
    $data = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(["error" => "Input JSON tidak valid: " . json_last_error_msg()]);
        return;
    }

    $name = $data['name'] ?? null;
    $dob = $data['dob'] ?? null;

    if (empty($name) || empty($dob)) {
        http_response_code(400);
        echo json_encode(["error" => "Nama dan Tanggal Lahir (dob) tidak boleh kosong"]);
        return;
    }

    if (!DateTime::createFromFormat('Y-m-d', $dob)) {
        http_response_code(400);
        echo json_encode(["error" => "Format Tanggal Lahir (dob) harus YYYY-MM-DD"]);
        return;
    }

    $stmt = $conn->prepare("UPDATE users SET name = ?, dob = ? WHERE firebase_uid = ?");
     if (!$stmt) {
        error_log("Prepare statement gagal (handleProfileUpdate): " . $conn->error);
        http_response_code(500);
        echo json_encode(["error" => "Terjadi kesalahan internal server."]);
        return;
    }
    $stmt->bind_param("sss", $name, $dob, $userId);
    if ($stmt->execute()) {
        if ($stmt->affected_rows > 0) {
            echo json_encode(["success" => true, "message" => "Profil berhasil diperbarui"]);
        } else {
             // Bisa jadi data yang dikirim sama persis, atau user tidak ada (meski sudah dicek ensureUserExists)
             echo json_encode(["success" => true, "message" => "Tidak ada perubahan pada data profil."]); // Kirim sukses jika tidak ada error
        }
    } else {
        error_log("Gagal update profil user {$userId}: " . $stmt->error);
        http_response_code(500);
        echo json_encode(["error" => "Gagal memperbarui profil."]);
    }
    $stmt->close();
}

function handleProfilePictureUpload($conn, $userId) {
    if (!isset($_FILES['image'])) {
        http_response_code(400);
        echo json_encode(["error" => "File gambar ('image') tidak ditemukan dalam request."]);
        return;
    }

    $file = $_FILES['image'];
    if ($file['error'] !== UPLOAD_ERR_OK) { /* Handle error */ return; }
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $fileType = mime_content_type($file['tmp_name']);
    if (!in_array($fileType, $allowedTypes)) { /* Handle error */ return; }
    $maxSize = 5 * 1024 * 1024; // 5 MB
    if ($file['size'] > $maxSize) { /* Handle error */ return; }

    $uploadDir = 'uploads/profile_pictures/';
    if (!file_exists($uploadDir)) {
        if (!mkdir($uploadDir, 0775, true)) { /* Handle error */ return; }
    }

    $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $fileExtension = preg_replace("/[^a-zA-Z0-9]/", "", $fileExtension);
    if (empty($fileExtension)) $fileExtension = 'jpg';
    $fileName = $userId . '_' . time() . '.' . $fileExtension;
    $uploadPath = $uploadDir . $fileName;

    if (move_uploaded_file($file['tmp_name'], $uploadPath)) {
        $fileUrl = "https://webtechsolution.my.id/kamuskorea/" . $uploadPath; // Ubah http ke https jika perlu

        $stmt = $conn->prepare("UPDATE users SET profile_picture_url = ? WHERE firebase_uid = ?");
        if (!$stmt) { /* Log error, Handle error */ return; }
        $stmt->bind_param("ss", $fileUrl, $userId);
        if ($stmt->execute()) {
             if ($stmt->affected_rows > 0) {
                 echo json_encode(["success" => true, "profilePictureUrl" => $fileUrl]);
             } else {
                  // Mungkin user tidak ditemukan
                  echo json_encode(["success" => false, "message" => "User tidak ditemukan untuk update URL foto."]);
             }
        } else {
            error_log("Gagal menyimpan URL gambar ke DB untuk user {$userId}: " . $stmt->error);
            http_response_code(500);
            echo json_encode(["error" => "Gagal menyimpan URL gambar ke database."]);
        }
        $stmt->close();

    } else {
        error_log("Gagal memindahkan file upload ke: " . $uploadPath);
        http_response_code(500);
        echo json_encode(["error" => "Gagal memproses upload file."]);
    }
}

function notFound() {
    http_response_code(404);
    echo json_encode(["error" => "Endpoint tidak ditemukan"]);
}

function unauthorized($message = "Akses tidak diizinkan. Token tidak valid atau tidak ada.") {
    http_response_code(401);
    echo json_encode(["error" => $message]);
}

?>