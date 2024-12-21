<?php
session_start();
include('database.php'); // Include database connection

// Check if the user is logged in as admin
if ($_SESSION['role'] !== 'admin') {
    header("Location: login.php"); // If not admin, redirect to login
    exit();
}

// Check if the form is submitted
if (isset($_POST['order_id']) && isset($_POST['status'])) {
    $order_id = $_POST['order_id'];
    $status = $_POST['status'];

    // Update the order status in the database
    $sql = "UPDATE orders SET order_status = ? WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("si", $status, $order_id);

    if ($stmt->execute()) {
        // Redirect back to the order management page with a success message
        header("Location: admin_orders.php?status=success");
    } else {
        // If update fails, redirect with an error message
        header("Location: admin_orders.php?status=error");
    }
} else {
    // If no order_id or status is passed, redirect back to the order management page
    header("Location: admin_orders.php?status=error");
}
?>