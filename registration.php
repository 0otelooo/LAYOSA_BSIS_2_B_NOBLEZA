<?php
// Start the session
session_start();

// Check if the form is submitted
if (isset($_POST["submit"])) {
    // Get the form data
    $username = trim($_POST["username"]);
    $email = trim($_POST["email"]);
    $password = trim($_POST["password"]);
    $confirmpassword = trim($_POST["confirmpassword"]);
    $phone = trim($_POST["phone"]);
    $address = trim($_POST["address"]);
    $role = "customer"; // Default role for registration is customer

    // Hash the password for security
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    // Initialize an error array to store validation errors
    $error = array();

    // Validate the input
    if (empty($username) || empty($email) || empty($password) || empty($confirmpassword) || empty($phone) || empty($address)) {
        array_push($error, "All fields are required.");
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        array_push($error, "Invalid email address.");
    }
    if (strlen($password) < 8) {
        array_push($error, "Password must be at least 8 characters long.");
    }
    if ($password !== $confirmpassword) {
        array_push($error, "Passwords do not match.");
    }

    // Include the database connection
    require_once "database.php";

    // Check if the email already exists in the database
    $sql = "SELECT * FROM register WHERE email = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        array_push($error, "Email is already registered.");
    }

    // Check if the phone number already exists in the database
    $sql = "SELECT * FROM register WHERE phone = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $phone);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        array_push($error, "Phone Number already used.");
    }

    // If no validation errors, insert the user into the database
    if (count($error) == 0) {
        $sql = "INSERT INTO register (username, email, password, phone, address, role) VALUES (?, ?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "ssssss", $username, $email, $passwordHash, $phone, $address, $role);
        $result = mysqli_stmt_execute($stmt);

        if ($result) {
            // Registration successful
            echo "<div class='alert alert-success'>Registration successful! Redirecting to login...</div>";
            header("refresh:3;url=login.php"); // Redirect to login page after 3 seconds
            exit();
        } else {
            array_push($error, "Something went wrong. Please try again.");
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register Page</title>
  <link rel="stylesheet" href="css/bootstrap.min.css">
</head>
<body class="bg-light">
  <div class="container vh-100 d-flex justify-content-center align-items-center">
    <div class="card shadow p-4" style="width: 100%; max-width: 400px;">
      <h2 class="fw-bold text-center mb-4">Register <svg xmlns="http://www.w3.org/2000/svg" width="27" height="27" fill="currentColor" class="bi bi-person-circle" viewBox="0 0 16 16">
        <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0" />
        <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1" />
      </svg></h2>
      
      <!-- Display validation errors if any -->
      <?php if (isset($error) && count($error) > 0): ?>
        <div class="alert alert-danger">
          <ul>
            <?php foreach ($error as $errors): ?>
              <li><?php echo htmlspecialchars($errors); ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>
      
      <form action="registration.php" method="POST">
        <!-- Username -->
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" class="form-control" name="username" placeholder="Enter your username" required>
        </div>
        
        <!-- Email -->
        <div class="mb-3">
          <label for="email" class="form-label">Email address</label>
          <input type="email" class="form-control" name="email" placeholder="Enter your email" required>
        </div>
        
        <!-- Password -->
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" name="password" placeholder="Enter your password" required>
        </div>
        
        <!-- Confirm Password -->
        <div class="mb-3">
          <label for="confirmpassword" class="form-label">Confirm Password</label>
          <input type="password" class="form-control" name="confirmpassword" placeholder="Confirm your password" required>
        </div>
        
        <!-- Phone -->
        <div class="mb-3">
          <label for="phone" class="form-label">Phone</label>
          <input type="tel" class="form-control" name="phone" placeholder="Enter your phone number" required>
        </div>
        
        <!-- Address -->
        <div class="mb-3">
          <label for="address" class="form-label">Address</label>
          <input type="text" class="form-control" name="address" placeholder="Enter your address" required>
        </div>
        
        <!-- Role (hidden as it's always 'customer') -->
        <input type="hidden" name="role" value="customer">
        
        <!-- Submit Button -->
        <button type="submit" name="submit" class="btn btn-primary w-100">Register</button>
      </form>
      
      <!-- Login Link -->
      <div class="text-center mt-3">
        Already have an account? <a href="login.php">Login here</a>
      </div>
    </div>
  </div>
</body>
</html>
