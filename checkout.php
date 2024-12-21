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

// Fetch cart items for the logged-in user
if (isset($_POST['cart_ids']) && !empty($_POST['cart_ids'])) {
    $cart_ids = implode(",", $_POST['cart_ids']); // Get selected cart item IDs
    $sql_cart = "SELECT cart.id AS cart_id, items.name, items.price, items.image_path, cart.quantity 
                 FROM cart 
                 JOIN items ON cart.item_id = items.id 
                 WHERE cart.user_id = ? AND cart.id IN ($cart_ids)";
    $stmt_cart = $conn->prepare($sql_cart);
    $stmt_cart->bind_param("i", $user_id);
    $stmt_cart->execute();
    $cart_result = $stmt_cart->get_result();
} else {
    header("Location: cart.php"); // Redirect to cart if no items are selected
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkout</title>
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
<header>Checkout</header>

<div class="container">
    <h2>Your Order Summary</h2>

    <h3>Customer Information</h3>
    <p>Username: <?php echo htmlspecialchars($user['username']); ?></p>
    <p>Email: <?php echo htmlspecialchars($user['email']); ?></p>
    <p>Address: <?php echo htmlspecialchars($user['address']); ?></p>
    <p>Contact Number: <?php echo htmlspecialchars($user['phone']); ?></p>


    <h3>Order Details</h3>
    <table>
        <thead>
            <tr>
                <th>Item</th>
                <th>Price</th>
                <th>Quantity</th>
                <th>Total</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $total = 0;
            if ($cart_result->num_rows > 0) {
                while ($row = $cart_result->fetch_assoc()) {
                    $item_total = $row['price'] * $row['quantity'];
                    $total += $item_total;
                    echo "<tr>
                            <td>{$row['name']}</td>
                            <td>₱" . number_format($row['price'], 2) . "</td>
                            <td>{$row['quantity']}</td>
                            <td>₱" . number_format($item_total, 2) . "</td>
                          </tr>";
                }
            } else {
                echo "<tr><td colspan='4'>No items selected.</td></tr>";
            }
            ?>
        </tbody>
    </table>

    <h3>Total: ₱<?php echo number_format($total, 2); ?></h3>

    <form action="process_checkout.php" method="POST">
        <!-- Hidden input to pass selected cart items to process_checkout.php -->
        <input type="hidden" name="cart_ids" value="<?php echo htmlspecialchars($cart_ids); ?>">

        <button type="submit">Confirm Order</button>
    </form>
</div>

</body>
</html>