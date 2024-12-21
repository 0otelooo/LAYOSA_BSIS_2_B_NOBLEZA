<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php"); // If not logged in, redirect to login page
    exit();
}

$user_id = $_SESSION['user_id'];

// Fetch updated order statuses for the logged-in user
$sql_orders = "
    SELECT 
        o.id AS order_id, 
        o.status 
    FROM 
        orders o
    WHERE 
        o.user_id = ?
    ORDER BY 
        o.created_at DESC";
$stmt = $conn->prepare($sql_orders);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result_orders = $stmt->get_result();

// Prepare the updated order statuses as an associative array
$orders = [];
while ($order = $result_orders->fetch_assoc()) {
    $orders[] = $order;
}

// Return the orders as a JSON response
echo json_encode($orders);
?>
