<?php
session_start();
ob_start();

// Display errors for debugging (optional)
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (isset($_POST["login"])) {
    $email = $_POST["email"];
    $password = $_POST["password"];

    require_once "database.php"; // Connect to your database

    // Prepare and execute the SQL query
    $sql = "SELECT * FROM register WHERE email = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);

    if ($user && password_verify($password, $user["password"])) {
        // Successful login
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];

        // Redirect based on user role
        if ($user['role'] === 'admin') {
            header("Location: homepageadmin.php");
        } else {
            header("Location: customershomepage.php");
        }
        exit();
    } else {
        // Invalid login credentials
        $login_error = "Invalid email or password.";
    }
}

ob_end_flush();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
</head>
<body class="bg-light">
    <div class="container vh-100 d-flex justify-content-center align-items-center">
        <div class="card shadow p-4" style="width: 100%; max-width: 400px;">
            <h2 class="fw-bold text-center mb-4">Login</h2>

            <!-- Show login error if there is one -->
            <?php if (isset($login_error)): ?>
                <div class="alert alert-danger"><?php echo $login_error; ?></div>
            <?php endif; ?>

            <!-- Login Form -->
            <form action="login.php" method="POST">
                <div class="mb-3">
                    <label for="email" class="form-label">Email address</label>
                    <input type="email" class="form-control" name="email" placeholder="Enter your email" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit" name="login" class="btn btn-primary w-100">Login</button>
            </form>

            <div class="text-center mt-3">
                Don't have an account? <a href="registration.php">Register here</a>
            </div>
        </div>
    </div>
</body>
</html>