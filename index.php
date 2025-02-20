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

    // Check if the username or email already exists
    $sql = "SELECT username, email FROM users WHERE username = ? OR email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($existing_username, $existing_email);
        $stmt->fetch(); // Fetch the existing values

        if ($existing_username === $username) {
            $_SESSION['message'] = "Username <strong>'$username'</strong> already exists! ";
        } elseif ($existing_email === $email) {
            $_SESSION['message'] = "Email ID <strong>'$email'</strong> already exists! <a href='login.php'>Login here</a>";
        }

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
    <link rel="stylesheet" href="style.css">
</head>


<body >
    <div class="container">
        <div class="row d-flex justify-content-center align-items-center">
            <div class="col-xl-4 col-md-6">

                <?php if (isset($_SESSION['message'])): ?>
                    <div class="alert alert-<?= $_SESSION['message_type']; ?>">
                        <?= $_SESSION['message']; ?>
                    </div>
                    <?php unset($_SESSION['message']);
                    unset($_SESSION['message_type']); ?>
                <?php endif; ?>
                <form method="post" action="" class="form">
                    <div class="flex-column text-center mb-3">
                        <label class="fs-3">Register Now</label>
                    </div>
                    <div class="flex-column">
                        <label>User Name </label>
                    </div>
                    <div class="inputForm">

                        <input type="text" name="username" class="input" placeholder="Username" required>
                    </div>
                    <div class="flex-column">
                        <label>Email </label>
                    </div>
                    <div class="inputForm">

                        <input type="email" name="email" class="input" placeholder="Email" required>
                    </div>
                    <div class="flex-column">
                        <label>Password </label>
                    </div>
                    <div class="inputForm">

                        <input type="password" name="password" class="input" placeholder="Password" required>
                    </div>
                    <button class="button-submit" type="submit" name="register">Sign Up</button>

                    <p class="p">Already have an account?<span class="span"><a href="login.php">Sign In</a></span>

                </form>
            </div>
        </div>
    </div>
</body>

</html>