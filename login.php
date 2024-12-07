<?php
session_start();  // Start a session to store user information

// Get the form data (entered by the user in the login form)
$email = $_POST['email'];
$password = $_POST['password'];

// Create a connection to the database
$conn = new mysqli('localhost', 'root', '', 'nyro');

if ($conn->connect_error) {
    die('Connection Failed: ' . $conn->connect_error);
} else {
    // Prepare the SQL statement to select user data based on username
    $stmt = $conn->prepare("SELECT register_id, email, password FROM register WHERE username = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    // Check if the user exists
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $dbEmail, $dbPassword);
        $stmt->fetch();

        // Verify the password entered by the user against the hashed password in the database
        if (password_verify($password, $dbPassword)) {
            // Password is correct, start the session
            $_SESSION['user_id'] = $id;
            $_SESSION['email'] = $dbEmail;

            // Redirect to a protected page (for example: dashboard.php)
            header("Location: index.php");
            exit();
        } else {
            // Password is incorrect
            echo "Incorrect password.";
            header("loginform.html");
        }
    } else {
        // User not found
        echo "No user found with that email.";
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();
}
?>
