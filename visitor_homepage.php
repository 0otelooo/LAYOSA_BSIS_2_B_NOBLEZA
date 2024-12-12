
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Nyro Homepage</title>
  
  
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
      width: 100%;  /* Ensure header takes up the full width */
    }
    /* Search bar placed above the logo */
    .search-bar-container {
      display: flex;
      justify-content: center;
      padding: 10px 0;
      background-color: #fff;
    }

    .search-bar input {
      width: 600px;
      padding: 10px;
      border-radius: 4px;
      border: 1px solid #ccc;
    }

    .search-bar button {
      padding: 8px 12px;
      background-color: #000000;
      border: none;
      color: white;
      cursor: pointer;
      border-radius: 4px;
    }

    .top-bar {
      padding: 0;
    }

    .top-bar .logo img {
      width: 100%;
      height:auto;
      display: block;
    }
    
    /* Sign In and Cart Button Styles */
.header-buttons {
  display: flex;
  gap: 15px;
  margin-left: 20px;
}

.header-buttons button {
  padding: 10px 20px;
  background-color: #000000; /* Same color for both buttons */
  border: none;
  color: white;
  font-size: 16px;
  cursor: pointer;
  border-radius: 4px;
}

.header-buttons button:hover {
  background-color: #00000039; /* Darken on hover */
}

/* Cart Button */
.header-buttons .cart {
  display: flex;
  align-items: center;  /* Vertically align items (image and text) */
  justify-content: center;  /* Ensure everything is centered */
  background-color: #000000;  /* Same color as Sign In button */
  border: none;
  color: white;  /* Text color */
  padding: 10px 20px;  /* Padding to increase button size */
  border-radius: 4px;
  font-size: 16px;
  cursor: pointer;
  position: relative;
}

/* Cart Image - half the size of the button */
.header-buttons .cart img {
  width: 20px;  /* Adjust image width */
  height: auto;  /* Maintain aspect ratio */
  margin-right: 10px;  /* Space between the image and the text */
}

/* Cart Button Text */
.header-buttons .cart span {
  color: white;  /* Text color */
  font-size: 14px;  /* Adjust text size */
}


    .navbar {
      background-color: #000000;
      color: white;
      padding: 10px 0;
      width: 100%;  /* Ensure navbar spans the entire width */
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
      color: rgb(255, 255, 255);
      text-decoration: none;
      font-size: 16px;
    }

    .navbar ul li a:hover {
      color: #faf7f75e;
  
    }
/* Carousel Container */
.carousel-container {
  position: relative;
  width: 100%;
  max-width: 600px;  /* Adjust this to your desired width */
  margin: 40px auto;
  overflow: hidden;
}

/* Carousel Images Container */
.carousel-images {
  display: flex;
  transition: transform 0.5s ease;
}

.carousel-image {
  width: 100%;
  flex-shrink: 0;
}

/* Adjust the image size */
.carousel-image img {
  width: 50%; /* Adjust the image width (e.g., 80% of the container width) */
  height: auto; /* Maintain aspect ratio */
  object-fit: cover;
  margin: 0 auto; /* Center the image horizontally */
}

/* Carousel Controls */
.carousel-controls {
  position: absolute;
  bottom: 10px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  gap: 10px;
}

.carousel-controls label {
  width: 15px;
  height: 15px;
  background-color: rgba(255, 255, 255, 0.6);
  border-radius: 50%;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

.carousel-controls label:hover {
  background-color: rgba(255, 255, 255, 0.9);
}

/* Switch between images based on radio button checked */
#carousel1:checked ~ .carousel-images {
  transform: translateX(0);
}

#carousel2:checked ~ .carousel-images {
  transform: translateX(-100%);
}

#carousel3:checked ~ .carousel-images {
  transform: translateX(-200%);
}

#carousel4:checked ~ .carousel-images {
  transform: translateX(-300%);
}

/* Auto scroll: Create keyframes to auto transition */
@keyframes auto-slide {
  0% { transform: translateX(0); }
  25% { transform: translateX(-100%); }
  50% { transform: translateX(-200%); }
  75% { transform: translateX(-300%); }
  100% { transform: translateX(0); }
}

.carousel-images {
  animation: auto-slide 16s infinite;
}


/* Auto scroll: Create keyframes to auto transition */
@keyframes auto-slide {
  0% { transform: translateX(0); }
  25% { transform: translateX(-100%); }
  50% { transform: translateX(-200%); }
  75% { transform: translateX(-300%); }
  100% { transform: translateX(0); }
}

.carousel-images {
  animation: auto-slide 16s infinite;
}
/* Main Banner Section */
.main-banner {
  width: 100%;  /* Full width for the banner */
  text-align: center;
  margin-top: 20px;
}

.main-banner .banner-image img {
  width: 100%;  /* Make the banner image take up the full width of the screen */
  height: auto;
}

/* Remove absolute positioning for text and let it flow below the image */
.main-banner .banner-text {
  margin-top: 20px;  /* Add space between the image and the text */
  color: #333;
}

.main-banner h2 {
  font-size: 36px;
  margin-bottom: 20px;
}

.shop-now-btn {
  background-color: #3e3e3e;
  padding: 12px 20px;
  font-size: 18px;
  color: white;
  border-radius: 5px;
  text-decoration: none;
}

.shop-now-btn:hover {
  background-color: #53251c;
}

    /* Featured Categories */
    .categories {
      padding: 40px 0;
      text-align: center;
    }n34e    .categories h2 {
      font-size: 28px;
      margin-bottom: 30px;
    }

    .category-list {
      display: flex;
      justify-content: center;
      gap: 20px;
    }

    .category-item {
      background-color: #fff;
      padding: 20px;
      border-radius: 8px;
      width: 300px;
      text-align: center;
    }

    .category-item img {
      width: 100%;
      height: auto;
      border-radius: 8px;
    }

    /* Featured Products */
    .featured-products {
      background-color: #fff;
      padding: 40px 0;
      text-align: center;
    }

    .featured-products h2 {
      font-size: 28px;
      margin-bottom: 30px;
    }

    .product-list {
      display: flex;
      justify-content: center;
      gap: 20px;
    }

    .product-item {
      background-color: #fff;
      padding: 20px;
      border-radius: 8px;
      width: 240px;  
      text-align: center;
      position: relative;
    }

    .product-item .badge{
      position:center;
      top: 10px;
      left: 10px;
      background-color: #383232;
      color: white;
      font-size: 12px;
      font-weight: bold;
      padding: 5px 10px;
      border-radius: 5px;
      box-shadow: 0 2px 5px rgba (0, 0, 0, 0.2);
    }

    .product-item img {
      width: 80%;  
      height: auto;  
      object-fit: cover;  
      border-radius: 8px;
    }

    .product-item button {
      background-color: #635f5e;
      padding: 10px 20px;
      font-size: 16px;
      color: white;
      border-radius: 5px;
      border: none;
      cursor: pointer;
      margin-top: 10px;
    }

    .product-item button:hover {
      background-color: #595554;
    }
  /* Styling for Other Products */
  .other-products {
    background-color: #fff;
    padding: 40px 0;
    text-align: center;
  }

  .other-products h2 {
    font-size: 28px;
    margin-bottom: 30px;
  }

  .product-list {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-evenly;
    gap: 20px;
  }

  .product-item {
    background-color: #fff;
    padding: 20px;
    border-radius: 8px;
    width: calc(33.333% - 20px); /* 3 products per row */
    text-align: center;
    box-sizing: border-box;
  }

  .product-item img {
      width: 80%;  
      height: auto;  
      object-fit: cover;  
      border-radius: 8px;
    }

  .product-item button {
    background-color: #413d3d;
    padding: 10px 20px;
    font-size: 16px;
    color: white;
    border-radius: 5px;
    border: none;
    cursor: pointer;
    margin-top: 10px;
  }

  .product-item button:hover {
    background-color: #5e5c5b;
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
  </style>
</head>
<body>

  <!-- Header Section -->
  <header class="header">
    <!-- Search bar placed above the logo -->
    <div class="search-bar-container">
      <div class="search-bar">
        <input type="text" placeholder="Search for products, brands, or styles...">
        <button>Search</button>
      </div>
      <div class="header-buttons">
        <!-- Sign In Button -->
        <a href="login.php">
          <button>Sign In</button>
          <a href="registration.php">
            <button>Sign Up</button>
        </a>
       
      </div>
    </div>
    <div class="top-bar">
      <div class="logo">
        <a href="#"><img src="shein.jpg" alt="Fashion Store"></a>
      </div>
    </div>
    <nav class="navbar">
      <ul>
        <li><a href="#">Women</a></li>
        <li><a href="#">Men</a></li>
        
      </ul>
    </nav>
    </div>    
    <!-- Carousel Section -->
<section class="carousel-container">
  <div class="carousel-images">
    <input type="radio" name="carousel" id="carousel1" checked>
    <input type="radio" name="carousel" id="carousel2">
    <input type="radio" name="carousel" id="carousel3">
    <input type="radio" name="carousel" id="carousel4">
    
    <!-- Carousel Images -->
    <div class="carousel-image">
      <img src="nb1.jpg" alt="Image 1">
    </div>
    <div class="carousel-image">
      <img src="nb2.jpg" alt="Image 2">
    </div>
    <div class="carousel-image">
      <img src="nb7.jpg" alt="Image 3">
    </div>
    <div class="carousel-image">
      <img src="nb8.jpg" alt="Image 4">
    </div>
    <div class="carousel-image">
      <img src="nb12.jpg" alt="Image 5">
    </div>
    <div class="carousel-image">
      <img src="nb14.jpg" alt="Image 6">
    </div>
  </div>

  <!-- Carousel Controls -->
  <div class="carousel-controls">
    <label for="carousel1"></label>
    <label for="carousel2"></label>
    <label for="carousel3"></label>
    <label for="carousel4"></label>
  </div>
</section>

  </header>

  <!-- Main Banner Section -->
  <section class="main-banner">
    <div class="banner-image">
      <img src="bigsale.jpg" alt="Main Banner">
    </div>
    <div class="banner-text">
      <h2>Up to 50% off on New Arrivals!</h2>
      <a href="registration.php" class="shop-now-btn">Shop Now</a>
    </div>
  </section>

  <!-- Featured Categories Section -->
  <section class="categories">
    <h2>Shop by Categories</h2>
    <div class="category-list">
      <div class="category-item">
        <img src="women.jpg" alt="Women">
        <h3>Women</h3>
      </div>
      <div class="category-item">
        <img src="men.jpg" alt="Men">
        <h3>Men</h3>
      </div>
    </div>
  </section>

  <!-- Featured Products Section -->
<section class="featured-products">
  <h2>Top Selling Products</h2>
  <div class="product-list">
    <div class="product-item">
      <div class="badge" >Best Seller</div>
      <img src="mens.jpg" alt="Product 1">
      <h3>Mystic Force</h3>
      <p>₱ ...</p>
      <div class="stars">
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
      </div>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <div class="product-item">
      <div class="badge" >Best Seller</div>
      <img src="boy.jpg" alt="Product 3">
      <h3>Urban Edge</h3>
      <p>₱ ...</p>
      <div class="stars">
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
      </div>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <div class="product-item">
      <div class="badge" >Best Seller</div>
      <img src="nb10.jpg" alt="Product 7">
      <h3>Mirage</h3>
      <p>₱ 0</p>
      <div class="stars">
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
        <span class="star"> &#9733;</span>
      </div>
      <a href="registration.php">
      <button>Add to Cart</button>
    </div>
  </div>
</section>

<!-- Other Products Section -->
<section class="other-products">
  <h2>Recommended</h2>
  <div class="product-list">
    <!-- Product 1 -->
    <div class="product-item">
      <img src="r1.jpg" alt="Product 1">
      <h3>Cloud Walkers</h3>
      <p>₱999.0</p>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <!-- Product 2 -->
    <div class="product-item">
      <img src="r2.jpg" alt="Product 2">
      <h3>City Slickers</h3>
      <p>₱754.0</p>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <!-- Product 3 -->
    <div class="product-item">
      <img src="r3.jpg" alt="Product 3">
      <h3>Trail Blaizers</h3>
      <p>₱689.0</p>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <!-- Product 4 -->
    <div class="product-item">
      <img src="r4.jpg" alt="Product 4">
      <h3>Zen Masters</h3>
      <p>₱458.0</p>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <!-- Product 5 -->
    <div class="product-item">
      <img src="r5.jpg" alt="Product 5">
      <h3>Pixel Perfect</h3>
      <p>₱577.0</p>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
    <!-- Product 6 -->
    <div class="product-item">
      <img src="r6.jpg" alt="Product 6">
      <h3>Sound Seakers</h3>
      <p>₱689.0</p>
      <a href="registration.php">
      <button>Add to Cart</button>
      </a>
    </div>
  </div>
</section>

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

</body>
</html>