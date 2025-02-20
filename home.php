<?php
// Secure session settings - Set BEFORE session_start()
ini_set('session.cookie_httponly', 1); // Prevent JavaScript access to session cookies
ini_set('session.cookie_secure', 1); // Enable HTTPS-only cookies (Only if HTTPS is used)
ini_set('session.use_strict_mode', 1); // Prevent session fixation

session_start(); // Start the session 

$timeout_duration = 10; // 15 minutes (900 seconds)

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Prevent session hijacking (IP & User-Agent Verification)
if (
    !isset($_SESSION['user_agent']) || !isset($_SESSION['ip_address']) ||
    $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT'] ||
    $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']
) {
    session_unset();
    session_destroy();
    header("Location: login.php?message=Session Hijacked");
    exit();
}

// **Check session expiration**
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout_duration)) {
    session_unset();
    session_destroy();
    session_start();
    $_SESSION['message'] = "Session expired. Please log in again.";
    header("Location: login.php");
    exit();
}

// **Update last activity timestamp**
$_SESSION['last_activity'] = time();

// **Regenerate session ID every request to prevent fixation attacks**
session_regenerate_id(true);

// Handle logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: login.php?message=You have been logged out.");
    exit();
}

// Get username from session
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : "User";

// **Calculate remaining session time for JavaScript**
$remaining_time = $_SESSION['last_activity'] + $timeout_duration - time();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <style>
        body {
            background-color: #f8f9fa;
        }

        .container {
            max-width: 500px;
            margin-top: 100px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
        }

        .logout-btn {
            background: red;
            color: white;
            padding: 10px;
            width: 100%;
            border: none;
            cursor: pointer;
            border-radius: 5px;
            text-decoration: none;
            text-align: center;
        }

        .logout-btn:hover {
            background: darkred;
        }
    </style>

    <script>
        // **JavaScript auto-logout timer**
        var remainingTime = <?php echo $remaining_time; ?>; // Get time left in PHP

        function startLogoutTimer() {
            if (remainingTime > 0) {
                setTimeout(function () {
                    alert("Your session has expired. You will be redirected to the login page.");
                    window.location.href = "login.php?message=Session Expired";
                }, remainingTime * 1000);
            }
        }

        // **Reset timer on user activity**
        function resetTimer() {
            fetch("session_refresh.php"); // Update session activity timestamp via AJAX
        }

        document.addEventListener("mousemove", resetTimer);
        document.addEventListener("keypress", resetTimer);

        // Start the logout timer when page loads
        window.onload = startLogoutTimer;
    </script>
</head>

<body>

    <div class="row d-flex justify-content-center">
        <div class="col-10 col-lg-12">
            <div class="container text-center">
                <h2 class="mb-3">Welcome, <?php echo $username; ?>!</h2>

                <!-- Display session messages -->
                <?php if (isset($_SESSION['message'])): ?>
                    <div class="alert alert-warning"><?php echo $_SESSION['message']; ?></div>
                    <?php unset($_SESSION['message']); ?>
                <?php endif; ?>

                <!-- Logout button -->
                <a href="?logout" class="logout-btn d-block">Logout</a>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS (Optional for interactivity) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

</body>

</html>
