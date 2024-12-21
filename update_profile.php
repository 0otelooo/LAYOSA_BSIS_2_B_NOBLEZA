<?php
session_start();
include 'database.php'; // Your database connection



// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$username = $_POST['username'];
$email = $_POST['email'];
$phone = $_POST['phone'];
$address = $_POST['address'];

// Update user data
$sql = "UPDATE register SET username = ?, email = ?, phone = ?, address = ? WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ssssi", $username, $email, $phone, $address, $user_id);

if ($stmt->execute()) {
    header("Location: customerprofile.php"); // Redirect back to profile page
    exit();
} else {
    echo "Error updating profile: " . $conn->error;
}

$conn->close();
?>