<?php
session_start();
$host = 'localhost';
$user = 'root';
$pass = '';
$dbname = 'user_auth';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error)
    die("Connection failed: " . $conn->connect_error);

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['register'])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $_SESSION['message'] = "User already exists! <a href='login.php'>Login here</a>";
        $_SESSION['message_type'] = "danger";
    } else {
        $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $password);

        if ($stmt->execute()) {
            $_SESSION['message'] = "Registration successful! Please log in.";
            $_SESSION['message_type'] = "success";
            header("Location: login.php");
            exit();
        } else {
            $_SESSION['message'] = "Registration failed. Try again.";
            $_SESSION['message_type'] = "danger";
        }
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body class="d-flex justify-content-center align-items-center vh-100 bg-light">

    <div class="row">
        <div class="col-12">
            <div style="border-radius: 20px;" class="container bg-white p-5  shadow-lg text-center">
                <h2 class="mb-3">Register Now</h2>
                <?php if (isset($_SESSION['message'])): ?>
                    <div class="alert alert-<?= $_SESSION['message_type']; ?>">
                        <?= $_SESSION['message']; ?>
                    </div>
                    <?php unset($_SESSION['message']);
                    unset($_SESSION['message_type']); ?>
                <?php endif; ?>
                <form method="post" action="">
                    <div class="mb-3">
                        <input type="text" name="username" class="form-control" placeholder="Username" required>
                    </div>
                    <div class="mb-3">
                        <input type="email" name="email" class="form-control" placeholder="Email" required>
                    </div>
                    <div class="mb-3">
                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                    </div>
                    <button class="btn btn-success w-100" type="submit" name="register">Register</button>
                </form>
                <p class="mt-3">Already have an account? <a href="login.php">Login Here</a></p>
            </div>
        </div>
    </div>

</body>

</html>