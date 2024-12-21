<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $item_id = $_POST['item_id'];
    $quantity = $_POST['quantity'];

    // Check if the item is already in the cart
    $sql = "SELECT * FROM cart WHERE user_id = ? AND item_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $user_id, $item_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // Update the quantity if the item already exists in the cart
        $sql = "UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND item_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iii", $quantity, $user_id, $item_id);
        $stmt->execute();
    } else {
        // Insert a new row if the item is not in the cart
        $sql = "INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iii", $user_id, $item_id, $quantity);
        $stmt->execute();
    }

    // Redirect back to the items page with a success message
    header("Location: addtocart.php?status=added");
    exit;
}
?>