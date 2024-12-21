<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Check if a cart ID is passed
if (isset($_POST['cart_id'])) {
    $cart_id = $_POST['cart_id'];

    // Prepare and execute the SQL to delete the item
    $sql = "DELETE FROM cart WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $cart_id);

    if ($stmt->execute()) {
        // Redirect back to the cart page
        header("Location: mycart.php");
        exit;
    } else {
        echo "Error removing item from the cart.";
    }
} else {
    // Redirect to the cart page if no cart ID is provided
    header("Location: mycart.php");
    exit;
}
?>