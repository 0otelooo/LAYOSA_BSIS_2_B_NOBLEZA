<?php
include 'dbb.php'; // Include database connection

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $order_id = $_POST['order_id'];
    $new_status = $_POST['status'];

    // Validate input
    if (!empty($order_id) && !empty($new_status)) {
        // Update order status in the database
        $stmt = $conn->prepare("UPDATE orders SET status = ? WHERE id = ?");
        $stmt->bind_param("si", $new_status, $order_id);

        if ($stmt->execute()) {
            echo "Order status updated successfully.";
        } else {
            echo "Error updating order status.";
        }
        $stmt->close();
    } else {
        echo "Invalid input.";
    }

    $conn->close();
    // Redirect back to the admin orders page
    header("Location: admin_orders.php");
    exit();
}
?>