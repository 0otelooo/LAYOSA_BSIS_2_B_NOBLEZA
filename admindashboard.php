<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the admin is logged in
if ($_SESSION['role'] !== 'admin') {
    header("Location: login.php"); // If not logged in as admin, redirect to login page
    exit();
}

// Fetching data for the dashboard
// 1. Sales Today vs Yesterday
$sql_sales_today = "SELECT SUM(i.price * o.quantity) AS total_sales_today 
                    FROM orders o 
                    JOIN items i ON o.item_id = i.id 
                    WHERE DATE(o.created_at) = CURDATE() AND o.status = 'Delivered'";
$result_sales_today = $conn->query($sql_sales_today);
$total_sales_today = $result_sales_today->fetch_assoc()['total_sales_today'];

$sql_sales_yesterday = "SELECT SUM(i.price * o.quantity) AS total_sales_yesterday 
                        FROM orders o 
                        JOIN items i ON o.item_id = i.id 
                        WHERE DATE(o.created_at) = CURDATE() - INTERVAL 1 DAY AND o.status = 'Delivered'";
$result_sales_yesterday = $conn->query($sql_sales_yesterday);
$total_sales_yesterday = $result_sales_yesterday->fetch_assoc()['total_sales_yesterday'];

// 2. Sales This Year vs Last Year
$sql_sales_this_year = "SELECT SUM(i.price * o.quantity) AS total_sales_this_year 
                        FROM orders o 
                        JOIN items i ON o.item_id = i.id 
                        WHERE YEAR(o.created_at) = YEAR(CURDATE()) AND o.status = 'Delivered'";
$result_sales_this_year = $conn->query($sql_sales_this_year);
$total_sales_this_year = $result_sales_this_year->fetch_assoc()['total_sales_this_year'];

$sql_sales_last_year = "SELECT SUM(i.price * o.quantity) AS total_sales_last_year 
                        FROM orders o 
                        JOIN items i ON o.item_id = i.id 
                        WHERE YEAR(o.created_at) = YEAR(CURDATE()) - 1 AND o.status = 'Delivered'";
$result_sales_last_year = $conn->query($sql_sales_last_year);
$total_sales_last_year = $result_sales_last_year->fetch_assoc()['total_sales_last_year'];

// 3. Inventory Report (Current Stock)
$sql_inventory = "SELECT i.name AS item_name, i.quantity
                  FROM items i 
                  ORDER BY i.quantity DESC";
$result_inventory = $conn->query($sql_inventory);

// 4. User Activity (Recent User Registrations)
$sql_user_activity = "SELECT username, email, created_at 
                      FROM register 
                      ORDER BY created_at DESC LIMIT 5";
$result_user_activity = $conn->query($sql_user_activity);

// 5. Item Movement Report (Recent Orders)
$sql_item_movement = "SELECT o.id AS order_id, i.name AS item_name, o.quantity, o.created_at 
                      FROM orders o 
                      JOIN items i ON o.item_id = i.id 
                      ORDER BY o.created_at DESC LIMIT 5";
$result_item_movement = $conn->query($sql_item_movement);

// 6. Top 10 Items (Highest Selling Items)
$sql_top_items = "SELECT i.name AS item_name, SUM(o.quantity) AS total_sold 
                  FROM orders o 
                  JOIN items i ON o.item_id = i.id 
                  GROUP BY i.name 
                  ORDER BY total_sold DESC LIMIT 10";
$result_top_items = $conn->query($sql_top_items);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background: #f4f6f9;
            margin: 0;
            padding: 0;
        }

        header {
            background: #333;
            color: #fff;
            padding: 20px;
            text-align: center;
            font-size: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 30px auto;
        }

        .card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        .card-body {
            padding: 20px;
        }

        .card-title {
            font-size: 1.5rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        table th, table td {
            padding: 10px;
            text-align: center;
        }

        table th {
            background: #333;
            color: #fff;
        }

        .card-header {
            background-color: #333;
            color: #fff;
            text-align: center;
        }

        /* Back button style */
        .back-button {
            position: absolute;
            top: 20px;
            left: 20px;
        }

    </style>
</head>
<body>

<!-- Back Button -->
<a href="homepageadmin.php" class="btn btn-dark btn-lg back-button">← Back</a>

<header>Admin Dashboard</header>

<div class="container">

    <!-- Sales Today vs Yesterday -->
    <div class="card">
        <div class="card-header">Sales Today vs Yesterday</div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Sales Today:</strong> $<?php echo number_format($total_sales_today, 2); ?></p>
                </div>
                <div class="col-md-6">
                    <p><strong>Sales Yesterday:</strong> $<?php echo number_format($total_sales_yesterday, 2); ?></p>
                </div>
            </div>
        </div>
    </div>

    <!-- Sales This Year vs Last Year -->
    <div class="card">
        <div class="card-header">Sales This Year vs Last Year</div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Sales This Year:</strong> $<?php echo number_format($total_sales_this_year, 2); ?></p>
                </div>
                <div class="col-md-6">
                    <p><strong>Sales Last Year:</strong> $<?php echo number_format($total_sales_last_year, 2); ?></p>
                </div>
            </div>
        </div>
    </div>

    <!-- Inventory Report -->
    <div class="card">
        <div class="card-header">Inventory Report</div>
        <div class="card-body">
            <table class="table">
                <thead>
                    <tr>
                        <th>Item Name</th>
                        <th>Stock Quantity</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($item = $result_inventory->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($item['item_name']); ?></td>
                            <td><?php echo $item['quantity']; ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- User Activity -->
    <div class="card">
        <div class="card-header">Recent User Activity</div>
        <div class="card-body">
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Registration Date</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($user = $result_user_activity->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                            <td><?php echo $user['created_at']; ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Item Movement Report -->
    <div class="card">
        <div class="card-header">Recent Item Movement</div>
        <div class="card-body">
            <table class="table">
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Item Name</th>
                        <th>Quantity</th>
                        <th>Order Date</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($movement = $result_item_movement->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $movement['order_id']; ?></td>
                            <td><?php echo htmlspecialchars($movement['item_name']); ?></td>
                            <td><?php echo $movement['quantity']; ?></td>
                            <td><?php echo $movement['created_at']; ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Top 10 Items -->
    <div class="card">
        <div class="card-header">Top 10 Items</div>
        <div class="card-body">
            <table class="table">
                <thead>
                    <tr>
                        <th>Item Name</th>
                        <th>Total Sold</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($top_item = $result_top_items->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($top_item['item_name']); ?></td>
                            <td><?php echo $top_item['total_sold']; ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>

<script src="js/bootstrap.bundle.js"></script>
</body>
</html>
