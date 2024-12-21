<?php
session_start(); // Start the session to access session variables

// Check if the user is logged in
if ($_SESSION['role'] !== 'admin') {
  header("Location: login.php"); // If not logged in as admin, redirect to login page
  exit();
}

// If logged in, display the admin orders page
?>


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <link rel="stylesheet" href="css/bootstrap.min.css">
  <title>Nyro - Welcome Back!</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
    }

    /* Header Section */
    .header {
      background-color: #fff;
      padding: 20px 0;
      width: 100%;
    }

    .header-container {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0 20px;
    }

    .logo img {
      width: 50px;
    }

    .search-bar {
      align-items: center;
    }

    .search-bar input {
      width: 300px;
      padding: 10px;
      border-radius: 4px;
      border: 1px solid #ccc;
    }

    .search-bar button {
      padding: 10px 20px;
      margin-right: none;
      margin-left: 10px;
      background-color: #000;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }

    .user-menu {
      display: flex;
      align-items: center;
      gap: 15px;
    }

    .user-menu button {
      padding: 10px 15px;
      background-color: #000;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }


    .navbar {
      background-color: #000;
      color: white;
      padding: 10px 0;
      width: 100%;
    }

    .navbar ul {
      display: flex;
      justify-content: center;
      list-style: none;
    }

    .navbar ul li {
      margin: 0 20px;
    }

    .navbar ul li a {
      color: white;
      text-decoration: none;
      font-size: 16px;
    }

    .navbar ul li a:hover {
      color: #ccc;
    }

    /* Main Banner Section */
    .main-banner {
      text-align: center;
      margin: 20px 0;
    }

    .main-banner img {
      width: 100%;
      max-height: 300px;
      object-fit: cover;
    }

    .main-banner h2 {
      margin: 20px 0;
      font-size: 24px;
    }

    .shop-now-btn {
      background-color: #000;
      color: white;
      padding: 12px 20px;
      border-radius: 4px;
      text-decoration: none;
    }

    .shop-now-btn:hover {
      background-color: #333;
    }

    /* Featured Products Section */
    .featured-products {
      padding: 20px;
    }

    .featured-products h2 {
      text-align: center;
      margin-bottom: 20px;
      font-size: 28px;
    }

    .product-list {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 20px;
    }

    .product-item {
      background-color: white;
      border: 1px solid #ccc;
      border-radius: 8px;
      padding: 10px;
      text-align: center;
      width: 15%;
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    }

    .product-item img {
      width: 100%;
      height: auto;
      border-radius: 8px;
    }

    .product-item h3 {
      font-size: 18px;
      margin: 10px 0;
    }

    .product-item p {
      font-size: 16px;
      color: #555;
    }

    .product-item button {
      padding: 10px 15px;
      background-color: #000;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }

    .product-item button:hover {
      background-color: #333;
    }

     /* Footer Section */
     .footer {
      background-color: #333;
      color: white;
      padding: 40px 0;
      text-align: center;
    }

    .footer .footer-links {
      display: flex;
      justify-content: center;
      gap: 50px;
      margin-bottom: 20px;
    }

    .footer .footer-links div {
      width: 200px;
      text-align: left;
    }

    .footer .footer-links h4 {
      margin-bottom: 10px;
      font-size: 18px;
      font-weight: bold;
    }

    .footer .footer-links ul {
      list-style: none;
    }

    .footer .footer-links ul li {
      margin-bottom: 10px;
    }

    .footer .footer-links ul li a {
      color: white;
      text-decoration: none;
    }

    .footer .footer-links ul li a:hover {
      color: #756d6b;
    }

    .footer p {
      margin-top: 20px;
      font-size: 14px;
    }
    .items{
      margin-right: 10px;
    }
    .dashboard{
      margin-right:15px;
      margin-left:10px;
    
    }
    .orders{
      margin: 10px;
    }

  </style>
</head>
<body>
  <!-- Header Section -->
  <header class="header">
    <div class="header-container">
      <div class="logo">
        <img src="logo.jpg" alt="Nyro Logo">
      </div>
      <div class="search-bar">
        <input type="text" placeholder="Search for products, brands, or styles...">
        <button>Search</button>
      </div>
      <div class="user-menu">  
      <span>Welcome, <?php echo isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Guest'; ?>!
      </span>
        <a class="orders" href="admin_orders.php">Manage Orders</a> 
        <a class="items" href="kristina.php">Manage Items</a>  
        <a class="dashboard" href="admindashboard.php">Admin Dashboard</a>
        <button onclick="location.href='logout.php'">Logout</button>     
      </div>
    </div>
  </header>

  <!-- Main Banner Section -->
  <section class="main-banner">
    <img src="banner.jpg" alt="Main Banner">
  </section>

  <!-- Featured Products Section -->
  <section class="other-products">
    <h3 style="text-align: center; margin-top: 10px; font-size: 2em;">MEN</h3>
  <div class="product-list">
    <!-- Product 1 -->
    <div class="product-item">
      <img src="r1.jpg" alt="Product 1">
      <h3>Cloud Walkers</h3>
      <p>₱999.0</p>
      
    </div>
    <!-- Product 2 -->
    <div class="product-item">
      <img src="r2.jpg" alt="Product 2">
      <h3>City Slickers</h3>
      <p>₱754.0</p>
     
    </div>
    <!-- Product 3 -->
    <div class="product-item">
      <img src="r3.jpg" alt="Product 3">
      <h3>Trail Blaizers</h3>
      <p>₱689.0</p>
      
    </div>
    <!-- Product 4 -->
    <div class="product-item">
      <img src="r4.jpg" alt="Product 4">
      <h3>Zen Masters</h3>
      <p>₱458.0</p>
      
    </div>
    <!-- Product 5 -->
    <div class="product-item">
      <img src="r5.jpg" alt="Product 5">
      <h3>Pixel Perfect</h3>
      <p>₱577.0</p>
      
    </div>
    <!-- Product 6 -->
    <div class="product-item">
      <img src="r6.jpg" alt="Product 6">
      <h3>Sound Seakers</h3>
      <p>₱689.0</p>
      
    </div>
  </div>
    <h3 style="text-align: center; margin-top: 10px; font-size: 2em;">WOMEN</h3>
    <div class="product-list">
    <!-- Product 1 -->
    <div class="product-item">
      <img src="w1.jpg" alt="Product 01">
      <h3>Blush Cascade</h3>
      <p>₱785.0</p>
      
    </div>
    <!-- Product 2 -->
    <div class="product-item">
      <img src="w2.jpg" alt="Product 02">
      <h3>Velvet Sprint</h3>
      <p>₱1,110.0</p>

    </div>
    <!-- Product 3 -->
    <div class="product-item">
      <img src="w3.jpg" alt="Product 03">
      <h3>Pastel Horizon</h3>
      <p>₱989.0</p>
      
    </div>
    <!-- Product 4 -->
    <div class="product-item">
      <img src="w4.jpg" alt="Product 04">
      <h3>Lunar Drift</h3>
      <p>₱1,352.0</p>

    </div>
    <!-- Product 5 -->
    <div class="product-item">
      <img src="w5.jpg" alt="Product 05">
      <h3>Ivory Crest</h3>
      <p>₱1,902.0</p>
      
    </div>
    <!-- Product 6 -->
    <div class="product-item">
      <img src="w6.jpg" alt="Product 06">
      <h3>Dawn Pulse</h3>
      <p>₱789.0</p>
      
    </div>
  </div>
</section>

  <!-- Footer Section -->
  <footer class="footer">
    <p>&copy; 2024 Nyro. All rights reserved.</p>
      <!-- Footer Section -->
  <footer class="footer">
    <div class="footer-links">
      <div>
        <h4>Customer Service</h4>
        <ul>
          <li><a href="#">Shipping and Returns</a></li>
          <li><a href="#">Help</a></li>
          <li><a href="#">Learn More</a></li>
        </ul>
      </div>
      <div>
        <h4>About Us</h4>
        <ul>
          <li><a href="#">We are a online shoe store that gives you the best service and quality.</a></li>
          <li><a href="#">Privacy Policy</a></li>
        </ul>
      </div>
      <div>
        <h4>Contact Information</h4>
        <ul>
          <li><a href="#">nyoofficial@gmail.com</a></li>
          <li><a href="#">09573698425</a></li>
          <li><a href="#">Polangui, Albay</a></li>
        </ul>
      </div>
    </div>
    <p>&copy; 2024 Nyro. All rights reserved.</p>
  </footer>
  </footer>
 
  
</body>
<script src="js/bootstrap.bundle.js"></script>
</html>
  