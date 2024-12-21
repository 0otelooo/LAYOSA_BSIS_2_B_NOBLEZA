<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Fetch customer information
$sql_user = "SELECT * FROM register WHERE id = ?";
$stmt_user = $conn->prepare($sql_user);
$stmt_user->bind_param("i", $user_id);
$stmt_user->execute();
$user_result = $stmt_user->get_result();
$user = $user_result->fetch_assoc();

// Check if cart IDs are posted
if (isset($_POST['cart_ids']) && !empty($_POST['cart_ids'])) {
    // Ensure cart_ids is an array before imploding
    $cart_ids = is_array($_POST['cart_ids']) ? $_POST['cart_ids'] : explode(',', $_POST['cart_ids']);
    $cart_ids_imploded = implode(",", $cart_ids); // Get selected cart item IDs

    // Fetch the selected cart items
    $sql_cart = "SELECT cart.id AS cart_id, cart.item_id, items.name, items.price, items.image_path, cart.quantity 
                 FROM cart 
                 JOIN items ON cart.item_id = items.id 
                 WHERE cart.user_id = ? AND cart.id IN ($cart_ids_imploded)";
    $stmt_cart = $conn->prepare($sql_cart);
    $stmt_cart->bind_param("i", $user_id);
    $stmt_cart->execute();
    $cart_result = $stmt_cart->get_result();
} else {
    header("Location: mycart.php"); // Redirect to cart if no items are selected
    exit;
}

// Insert order into orders table
if ($cart_result->num_rows > 0) {
    // Process each cart item
    while ($row = $cart_result->fetch_assoc()) {
        $item_id = $row['item_id'];
        $quantity = $row['quantity'];
        $total_price = $row['price'] * $quantity;

        // Insert order for each cart item
        $sql_order = "INSERT INTO orders (user_id, item_id, quantity, order_status, status) 
                      VALUES (?, ?, ?, 'Pending', 'Pending')";
        $stmt_order = $conn->prepare($sql_order);
        $stmt_order->bind_param("iii", $user_id, $item_id, $quantity);
        $stmt_order->execute();
    }

    // Remove items from cart
    $sql_remove_from_cart = "DELETE FROM cart WHERE id IN ($cart_ids_imploded) AND user_id = ?";
    $stmt_remove_from_cart = $conn->prepare($sql_remove_from_cart);
    $stmt_remove_from_cart->bind_param("i", $user_id);
    $stmt_remove_from_cart->execute();

    // Redirect to a success page
    header("Location: mycart.php?success=1");
    exit;

} else {
    echo "No items found for checkout.";
}
?>
