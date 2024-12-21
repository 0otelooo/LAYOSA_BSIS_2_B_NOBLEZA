<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the admin is logged in
if ($_SESSION['role'] !== 'admin') {
    header("Location: login.php"); // If not logged in as admin, redirect to login page
    exit();
  }

// Handle status updates
if (isset($_POST['update_status'])) {
    $order_id = $_POST['order_id'];
    $new_status = $_POST['status'];

    $sql_update = "UPDATE orders SET status = ? WHERE id = ?";
    $stmt_update = $conn->prepare($sql_update);
    $stmt_update->bind_param("si", $new_status, $order_id);
    $stmt_update->execute();

    header("Location: admin_orders.php?status_updated=1");
    exit;
}

// Fetch all orders with user information and item details
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
    ORDER BY 
        o.created_at DESC";
$result_orders = $conn->query($sql_orders);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Order Management</title>
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

        select, button {
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 6px;
            font-size: 0.9rem;
            cursor: pointer;
        }

        button {
            background: #333;
            color: white;
            border: none;
            transition: background 0.3s ease;
        }

        button:hover {
            background: #555;
        }

        .status-updated {
            color: green;
            text-align: center;
            margin-bottom: 15px;
            font-size: 1.1rem;
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
<div class="container mt-4">
    <!-- Back Button -->
    <div class=" mb-4">
        <a href="homepageadmin.php" class="btn btn-dark btn-lg">← Back</a>
    </div>

    <!-- Admin Order Management Title -->
    <h1 class="text-center mb-4">Admin Order Management</h1>

    <?php if (isset($_GET['status_updated'])): ?>
        <p style="color: green;">Order status updated successfully!</p>
    <?php endif; ?>

    <!-- Table with orders -->
    <table class="table table-bordered">
        <thead>
            <tr>
                <th>Order ID</th>
                <th>Customer Name</th>
                <th>Email</th>
                <th>Item Name</th>
                <th>Quantity</th>
                <th>Total Price</th>
                <th>Status</th>
                <th>Order Date</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php if ($result_orders->num_rows > 0): ?>
                <?php while ($order = $result_orders->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo $order['order_id']; ?></td>
                        <td><?php echo htmlspecialchars($order['customer_name']); ?></td>
                        <td><?php echo htmlspecialchars($order['customer_email']); ?></td>
                        <td><?php echo htmlspecialchars($order['item_name']); ?></td>
                        <td><?php echo $order['quantity']; ?></td>
                        <td>$<?php echo number_format($order['item_price'] * $order['quantity'], 2); ?></td>
                        <td><?php echo htmlspecialchars($order['status']); ?></td>
                        <td><?php echo $order['created_at']; ?></td>
                        <td>
                            <form action="admin_orders.php" method="POST">
                                <input type="hidden" name="order_id" value="<?php echo $order['order_id']; ?>">
                                <select name="status" class="form-select">
                                    <option value="Pending" <?php if ($order['status'] === 'Pending') echo 'selected'; ?>>Pending</option>
                                    <option value="Confirmed" <?php if ($order['status'] === 'Confirmed') echo 'selected'; ?>>Confirmed</option>
                                    <option value="Shipped" <?php if ($order['status'] === 'Shipped') echo 'selected'; ?>>Shipped</option>
                                    <option value="Delivered" <?php if ($order['status'] === 'Delivered') echo 'selected'; ?>>Delivered</option>
                                    <option value="Paid" <?php if ($order['status'] === 'Paid') echo 'selected'; ?>>Paid</option>
                                </select>
                                <button type="submit" name="update_status" class="btn btn-primary mt-2">Update</button>
                            </form>
                        </td>
                    </tr>
                <?php endwhile; ?>
            <?php else: ?>
                <tr>
                    <td colspan="9" class="text-center">No orders found.</td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>
</div>
</body>
                <script src="js/bootstrap.bundle.js"> </script>
</html>
