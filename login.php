

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Page</title>
  <!-- Bootstrap CSS -->
   <link rel="stylesheet" href="css/bootstrap.min.css">
  
</head>
<body class="bg-light">

  <div class="container vh-100 d-flex justify-content-center align-items-center">

  
  <?php
session_start();
ob_start(); // Start output buffering

if (isset($_POST["Confirm"])) {
    $email = $_POST["email"];
    $password = $_POST["password"];
    require_once "database.php";

    $sql = "SELECT * FROM register WHERE email= '$email'";
    $result = mysqli_query($conn, $sql);
    $user = mysqli_fetch_array($result, MYSQLI_ASSOC);

    if ($user) {
        if (password_verify($password, $user["password"])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role']; // Assuming 'role' exists in the database
            $_SESSION['name'] = $user['name'];

            // Redirect based on role
            if ($user['role'] === 'admin') {
                header("Location: homepageadmin.php");
                die();
            } else {
                header("Location: customershomepage.php");
                die();
            }
        } else {
            echo "<div class='alert alert-danger'>Password does not match</div>";
        }
    } else {
        echo "<div class='alert alert-danger'>Email does not exist</div>";
    }
}

  ob_end_flush(); // End output buffering
?>

    <div class="card shadow p-4" style="width: 100%; max-width: 400px;">
      <div class="text-center mb-4">
        <h2 class="fw-bold">Login <svg xmlns="http://www.w3.org/2000/svg" width="25" height="25" fill="currentColor" class="bi bi-person-circle" viewBox="0 0 16 16">
            <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0"/>
            <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1"/>
          </svg></h2>
      </div>
      <form action="login.php" method="POST">
        <!-- Email Input -->
        <div class="mb-3">
          <label for="email" class="form-label">Email address</label>
          <input type="email" class="form-control" name="email" placeholder="Enter your email"  required >
        </div>

        <!-- Password Input -->
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" name="password" placeholder="Enter your password"required >
        </div>

        <!-- Login Button -->
        <div class="d-grid mt-4">
          <input type="submit" class="form-control btn btn-primary" value="Login" name="Confirm">
        </div>
      </form>

      <!-- Register Link -->
      <div class="text-center mt-3">
        <p class="mb-0">Don't have an account? <a href="register.html" class="text-decoration-none">Register</a></p>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="js/bootstrap.bundle.js"></script>
</body>
</html>
