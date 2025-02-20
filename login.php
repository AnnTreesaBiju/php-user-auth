<?php
// Secure session settings - Set BEFORE session_start()
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);

session_start();

// Database connection
$host = 'localhost';
$user = 'root';
$pass = ''; 
$dbname = 'user_auth';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error)
    die("Connection failed: " . $conn->connect_error);

$message = "";

// ✅ Fix: Check if 'message' exists before displaying
if (isset($_SESSION['message'])) {
    $message_type = isset($_SESSION['message_type']) ? $_SESSION['message_type'] : "danger"; // Default to danger
    $message = "<div class='alert alert-$message_type'>" . $_SESSION['message'] . "</div>";
    unset($_SESSION['message']);
    unset($_SESSION['message_type']);
}

// ✅ Fix: Store session timeout message before redirecting
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 900)) { // 900 seconds = 15 minutes
    session_unset();
    session_destroy();
    session_start();
    $_SESSION['message'] = "Session expired. Please log in again.";
    $_SESSION['message_type'] = "danger";
    header("Location: login.php");
    exit();
}
$_SESSION['last_activity'] = time(); // Reset activity timer

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($row = $result->fetch_assoc()) {
        if (password_verify($password, $row['password_hash'])) {
            // Session Fixation Protection
            session_regenerate_id(true);
            
            // Store session variables
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $username;
            $_SESSION['last_activity'] = time();
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
            $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];

            header("Location: home.php");
            exit();
        } else {
            $message = "<div class='alert alert-danger'>Invalid password!</div>";
        }
    } else {
        $message = "<div class='alert alert-danger'>User not found!</div>";
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body class="d-flex justify-content-center align-items-center vh-100 bg-light">
    <div class="row">
        <div class="col-12">
            <div style="border-radius: 20px;" class="container bg-white p-3 p-lg-5 shadow-lg text-center">
                <h2 class="mb-3">Login</h2>
                <?php if (!empty($message)) echo $message; ?>
                <form method="post" action="">
                    <div class="mb-3">
                        <input type="text" name="username" class="form-control" placeholder="Username" required>
                    </div>
                    <div class="mb-3">
                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                    </div>
                    <button class="btn btn-primary w-100" type="submit" name="login">Login</button>
                </form>
                <p class="mt-3">Don't have an account? <a href="index.php">Register Here</a></p>
            </div>
        </div>
    </div>
</body>

</html>
