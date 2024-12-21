<?php
session_start();
include('database.php'); // Include the database connection file

if (isset($_GET['status']) && $_GET['status'] == 'added') {
    echo "<p style='color: green; text-align: center;'>Item added to cart successfully!</p>";
}

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Fetch items from the database
$sql = "SELECT * FROM items";
$result = $conn->query($sql);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Order Items</title>

    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #f5f7fa, #c3cfe2);
            margin: 0;
            padding: 0;
            color: #333;
        }

        header {
            background: rgb(41, 40, 40);
            color: #fff;
            padding: 15px;
            text-align: center;
            font-size: 1.5rem;
            box-shadow: 0 4px 6px rgba(24, 24, 24, 0.1);
        }

        .header-buttons {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 20px;
            margin-top: 20px;
        }

        .header-buttons a {
            text-decoration: none;
            background-color: rgb(45, 39, 39);
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            font-weight: bold;
        }

        .container {
            max-width: 1000px;
            margin: 30px auto;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            padding: 20px;
        }

        table {
            width: 100%;
            margin: 20px 0;
            border-collapse: separate;
            border-spacing: 0 10px;
        }

        table thead th {
            background: rgb(12, 12, 12);
            color: white;
            padding: 12px;
            border-radius: 8px 8px 0 0;
            font-weight: 600;
        }

        table tbody tr {
            background: #f8f9fa;
            border-radius: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        table tbody tr:hover {
            transform: scale(1.02);
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }

        table tbody td {
            padding: 12px;
            text-align: center;
        }

        table tbody td img {
            max-width: 70px;
            border-radius: 8px;
        }

        input[type="number"] {
            width: 80px;
            padding: 5px;
            border: 1px solid #ced4da;
            border-radius: 5px;
            text-align: center;
        }

        button {
            background-color: rgb(18, 18, 19);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.3s ease;
            font-weight: 500;
        }

        button:hover {
            background-color: rgb(14, 14, 16);
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
        }

        @media (max-width: 768px) {
            input[type="number"], button {
                width: 100%;
                margin-top: 5px;
            }
        }
    </style>
</head>
<body>
    <header>Order Items</header>

    <div class="header-buttons">
        <a href="customershomepage.php">← Back</a>
        <a href="mycart.php">View Cart</a>
    </div>

    <div class="container">
        <table border="1">
            <thead>
                <tr>
                    <th>Item Name</th>
                    <th>Price</th>
                    <th>Description</th>
                    <th>Quantity</th>
                    <th>Gender</th>
                    <th>Image</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ($result->num_rows > 0) {
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>
                                <td>{$row['name']}</td>
                                <td>₱{$row['price']}</td>
                                <td>{$row['description']}</td>
                                <td>{$row['quantity']}</td>
                                <td>{$row['gender']}</td>
                                <td><img src='{$row['image_path']}' alt='{$row['name']}' width='100'></td>
                                <td>
                                    <form action='add_to_cart.php' method='POST'>
                                        <input type='hidden' name='item_id' value='{$row['id']}'>
                                        <input type='number' name='quantity' min='1' max='{$row['quantity']}' required>
                                        <button type='submit'>Add to Cart</button>
                                    </form>
                                </td>
                              </tr>";
                    }
                } else {
                    echo "<tr><td colspan='7'>No items available.</td></tr>";
                }
                ?>
            </tbody>
        </table>
    </div>
</body>
</html>
