<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get the item ID and quantity from the form
    $item_id = $_POST['item_id'];
    $quantity = $_POST['quantity'];

    // Check if the requested quantity is available
    $sql = "SELECT quantity FROM items WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $item_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $item = $result->fetch_assoc();

    if ($item && $item['quantity'] >= $quantity) {
        // Insert the order into the orders table
        $sql = "INSERT INTO orders (user_id, item_id, quantity) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iii", $user_id, $item_id, $quantity);
        $stmt->execute();

        // Update the item quantity
        $new_quantity = $item['quantity'] - $quantity;
        $sql = "UPDATE items SET quantity = ? WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $new_quantity, $item_id);
        $stmt->execute();

        echo "Order placed successfully!";
    } else {
        echo "Not enough quantity available.";
    }
}
?>