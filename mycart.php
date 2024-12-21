<?php
session_start();
include('database.php'); // Include the database connection file

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Fetch cart items for the logged-in user
$sql = "SELECT cart.id AS cart_id, items.name, items.price, items.image_path, cart.quantity 
        FROM cart 
        JOIN items ON cart.item_id = items.id 
        WHERE cart.user_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your Cart</title>
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

        input[type="number"] {
            width: 80px;
            padding: 5px;
            border: 1px solid #ced4da;
            border-radius: 5px;
            text-align: center;
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
        }
    </style>
    <script>
        function updateRowTotal(input) {
            const row = input.closest('tr'); // Find the closest table row
            const price = parseFloat(row.querySelector('.item-price').innerText.replace('₱', '')); // Get the item price
            const quantity = parseInt(input.value) || 0; // Get the quantity value or default to 0
            const rowTotalElement = row.querySelector('.row-total'); // Get the row total element

            // Update the row total
            const newTotal = price * quantity;
            rowTotalElement.innerText = `₱${newTotal.toFixed(2)}`;

            // Update the grand total
            updateTotal();
        }

        function updateTotal() {
            let total = 0;
            const rows = document.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const checkbox = row.querySelector('input[type="checkbox"]');
                const rowTotal = parseFloat(row.querySelector('.row-total').innerText.replace('₱', ''));

                if (checkbox && checkbox.checked) {
                    total += rowTotal;
                }
            });

            document.getElementById('grand-total').innerText = `₱${total.toFixed(2)}`;
        }

        document.addEventListener('DOMContentLoaded', () => {
            const checkboxes = document.querySelectorAll('input[type="checkbox"]');
            const quantityInputs = document.querySelectorAll('input[type="number"]');

            checkboxes.forEach(checkbox => checkbox.addEventListener('change', updateTotal));
            quantityInputs.forEach(input => input.addEventListener('input', () => updateRowTotal(input)));
        });
    </script>
</head>
<body>
<header>Your Cart</header>

<div class="container">
    <a href="addtocart.php">← Back to Shop</a>
    
    <form action="checkout.php" method="POST">
        <table>
            <thead>
                <tr>
                    <th>Select</th>
                    <th>Item</th>
                    <th>Price</th>
                    <th>Quantity</th>
                    <th>Total</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ($result->num_rows > 0) {
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>
                                <td><input type='checkbox' name='cart_ids[]' value='{$row['cart_id']}'></td>
                                <td>
                                    <img src='{$row['image_path']}' alt='{$row['name']}' width='70'><br>
                                    {$row['name']}
                                </td>
                                <td class='item-price'>₱{$row['price']}</td>
                                <td>
                                    <input type='number' name='quantities[{$row['cart_id']}]' 
                                           value='{$row['quantity']}' 
                                           min='1' 
                                           max='{$row['quantity']}' 
                                           oninput='updateRowTotal(this)'>
                                </td>
                                <td class='row-total'>₱" . ($row['price'] * $row['quantity']) . "</td>
                                <td>
                                    <form action='remove_from_cart.php' method='POST'>
                                        <input type='hidden' name='cart_id' value='{$row['cart_id']}'>
                                        <button type='submit'>Remove</button>
                                    </form>
                                </td>
                              </tr>";
                    }
                } else {
                    echo "<tr><td colspan='6'>Your cart is empty.</td></tr>";
                }
                ?>
            </tbody>
        </table>

        <h3>Total: <span id="grand-total">₱0.00</span></h3>

        <?php if ($result->num_rows > 0) : ?>
            <button type="submit">Proceed to Checkout</button>
        <?php endif; ?>
    </form>
</div>

</body>
</html>