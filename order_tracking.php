<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php"); // If not logged in, redirect to login page
    exit();
}

$user_id = $_SESSION['user_id'];

// Fetch orders for the logged-in user, separated by status
$sql_orders = "
    SELECT 
        o.id AS order_id, 
        o.user_id, 
        o.item_id, 
        o.quantity, 
        o.status, 
        o.created_at, 
        r.username AS customer_name, 
        r.email AS customer_email, 
        i.name AS item_name, 
        i.price AS item_price 
    FROM 
        orders o
    JOIN 
        register r ON o.user_id = r.id
    JOIN 
        items i ON o.item_id = i.id
    WHERE 
        o.user_id = ?
    ORDER BY 
        o.created_at DESC";
$stmt = $conn->prepare($sql_orders);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result_orders = $stmt->get_result();

$orders_by_status = [
    'Pending' => [],
    'Confirmed' => [],
    'Shipped' => [],
    'Delivered' => [],
    'Paid' => []
];

// Group orders by status
while ($order = $result_orders->fetch_assoc()) {
    $orders_by_status[$order['status']][] = $order;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your Orders</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #f5f7fa, #c3cfe2);
            margin: 0;
            padding: 0;
            color: #333;
        }

        header {
            background: #333;
            color: #fff;
            padding: 20px;
            text-align: center;
            font-size: 1.8rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .container {
            max-width: 1200px;
            margin: 30px auto;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
            padding: 20px;
            overflow: hidden;
        }

        table {
            width: 100%;
            margin: 20px 0;
            border-collapse: separate;
            border-spacing: 0 10px;
        }

        table thead th {
            background: #333;
            color: #fff;
            padding: 12px;
            text-align: center;
            font-weight: bold;
        }

        table tbody tr {
            background: #f8f9fa;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        table tbody tr:hover {
            transform: scale(1.02);
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }

        table tbody td {
            padding: 12px;
            text-align: center;
            vertical-align: middle;
        }

        .status-title {
            font-size: 1.5rem;
            color: #333;
            margin-top: 20px;
            font-weight: bold;
        }

        .empty-message {
            text-align: center;
            font-size: 1.2rem;
            color: #666;
        }

    </style>
</head>
<body>

<header>Your Order Tracking</header>
<div style="padding: 10px;">
    <a href="customershomepage.php" style="
        text-decoration: none;
        background-color:rgb(45, 39, 39);
        color: white;
        padding: 10px 20px;
        border-radius: 4px;
        font-weight: bold;
    ">←Back</a>
  </div>
<div class="container" id="orders-container">
    <?php foreach ($orders_by_status as $status => $orders): ?>
        <?php if (!empty($orders)): ?>
            <h2 class="status-title"><?php echo $status; ?> Orders</h2>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Item Name</th>
                        <th>Quantity</th>
                        <th>Total Price</th>
                        <th>Status</th>
                        <th>Order Date</th>
                    </tr>
                </thead>
                <tbody id="order-table-body-<?php echo $status; ?>">
                    <?php foreach ($orders as $order): ?>
                        <tr id="order-<?php echo $order['order_id']; ?>">
                            <td><?php echo $order['order_id']; ?></td>
                            <td><?php echo htmlspecialchars($order['item_name']); ?></td>
                            <td><?php echo $order['quantity']; ?></td>
                            <td>$<?php echo number_format($order['item_price'] * $order['quantity'], 2); ?></td>
                            <td class="status"><?php echo htmlspecialchars($order['status']); ?></td>
                            <td><?php echo $order['created_at']; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        
        <?php endif; ?>
    <?php endforeach; ?>
</div>

<script src="js/bootstrap.bundle.js"></script>
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
// Function to fetch the latest order statuses
function fetchOrderStatus() {
    $.ajax({
        url: 'order_status_update.php', // PHP script to fetch updated order statuses
        type: 'GET',
        success: function(response) {
            const orders = JSON.parse(response);
            orders.forEach(order => {
                // Update the status of the order in the table
                $('#order-' + order.order_id + ' .status').text(order.status);
            });
        }
    });
}

// Set an interval to update the order statuses every 5 seconds
setInterval(fetchOrderStatus, 5000);
</script>

</body>
</html>
