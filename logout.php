<?php
// Start the session
session_start();

// Destroy all session data
session_unset();
session_destroy();

// Redirect to the login or homepage
header("Location: login.php"); // Change 'index.html' to your login or homepage
exit;
?>