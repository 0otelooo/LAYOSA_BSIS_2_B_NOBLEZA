<?php
session_start();
include 'database.php'; // Include your database connection file

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php"); // Redirect if not logged in
    exit();
}



$user_id = $_SESSION['user_id'];

// Fetch user data
$sql = "SELECT username, email, phone, address FROM register WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc(); // Store user data
} else {
    echo "User not found!";
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Customer Profile</title>
  <style>
    /* General Styles */
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background: linear-gradient(to bottom right, #676262, #e4e8e8);
      color: #333;
    }

    .container {
      max-width: 800px;
      margin: 50px auto;
      padding: 20px;
      background-color: #fff;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }

    h1 {
      text-align: center;
      color: #444;
    }

    .profile-info label {
      display: block;
      font-weight: bold;
      margin-bottom: 5px;
    }

    .profile-info input, .profile-info textarea {
      width: 100%;
      padding: 10px;
      margin-bottom: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
    }

    .buttons {
      display: flex;
      justify-content: center;
      gap: 10px;
    }

    .buttons button {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      background-color: #000000;
      color: white;
    }

    .buttons button:hover {
      background-color: #616362;
    }
  </style>
</head>
<body>

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

<div class="container">
  <h1>Customer Profile</h1>
  <form action="update_profile.php" method="POST">
    <div class="profile-info">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>

      <label for="email">Email Address</label>
      <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" readonly>

      <label for="phone">Phone Number</label>
      <input type="tel" id="phone" name="phone" value="<?php echo htmlspecialchars($user['phone']); ?>" required>

      <label for="address">Address</label>
      <textarea id="address" name="address" rows="3"><?php echo htmlspecialchars($user['address']); ?></textarea>
    </div>

    <div class="buttons">
      <button type="submit">Save</button>
      <button type="reset">Cancel</button>
    </div>
  </form>
</div>
</body>
</html>
