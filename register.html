
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register Page</title>
  <!-- Bootstrap CSS -->
   <link rel="stylesheet" href="css/bootstrap.min.css">
   
   
  
</head>
<body class="bg-light">

  <div class="container vh-100 d-flex justify-content-center align-items-center">
    <?php 
    if(isset($_POST["submit"])){
        $username=$_POST["username"];
        $email=$_POST["email"];
        $password=$_POST["password"];
        $confirmpassword=$_POST["confirmpassword"];
        $phone=$_POST["phone"];
        $address=$_POST["address"];
        $role=$_POST["role"];

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $error=array();

        
        if(empty($username) OR empty($email) OR empty($password) OR empty($confirmpassword) OR empty($confirmpassword) OR empty($phone)
                OR empty($address) OR empty($role) ){
            array_push($error,"Please input all the fields");
        }
        if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
            array_push($error, "Enter a valid Email Address");
        }
        if(strlen($password)<8){
            array_push($error, "Password must be at least 8 characters long");
        }
        if($password !== $confirmpassword){
            array_push($error, "Password does not match");
        }
        

        require_once "database.php";

        $sql= "SELECT *FROM register WHERE email='$email'";
        $result = mysqli_query($conn,$sql);
        $rowcount = mysqli_num_rows($result);
        if($rowcount>0){
            array_push($error, "Email already exist!");
        }       
        if(count($error)>0){
               
            foreach($error   as $errors){
            }
        
        }  else{
            
            $sql = "INSERT INTO register (username,email,password,phone,address,role) VALUES (?, ?, ?,?,?,?)";
            $stmt = mysqli_stmt_init($conn);
           $prepareStmt= mysqli_stmt_prepare($stmt,$sql);
           if($prepareStmt){
            mysqli_stmt_bind_param($stmt, "ssssss", $username, $email, $passwordHash, $phone, $address,$role);
            mysqli_stmt_execute($stmt);
            echo "<div class='alert alert-success'>Registered Successfully</div>";
            header("Location: login.php");
            die();
           }
           else{
            die("Something went wrong!");
           }
            }
        }
        

    ?>
    <div class="card shadow p-4" style="width: 100%; max-width: 400px;">
  <div class="text-center mb-4">
    <h2 class="fw-bold">Register <svg xmlns="http://www.w3.org/2000/svg" width="27" height="27" fill="currentColor" class="bi bi-person-circle" viewBox="0 0 16 16">
        <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0" />
        <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1" />
      </svg></h2>
  </div>

  <form action="registration.php" method="post">
    <!-- Error Messages -->
    <?php
    if (isset($_POST["submit"]) && count($error) > 0) {
      echo "<div class='error-box'>";
      echo "<ul>";
      foreach ($error as $errors) {
        echo "<li><i class='bi bi-exclamation-triangle-fill text-danger'></i> $errors </li>";
      }
      echo "</ul>";
      echo "</div>";
    }
    ?>
    <!-- Username Input -->
    <div class="mb-2.5">
      <label for="email" class="form-label">Username</label>
      <input type="text" class="form-control" name="username" placeholder="Enter your Username">
    </div>
    <!-- Email Input -->
    <div class="mb-2.5">
      <label for="email" class="form-label">Email address</label>
      <input type="email" class="form-control" name="email" placeholder="Enter your email">
    </div>

    <!-- Password Input -->
    <div class="mb-2.5">
      <label for="password" class="form-label">Password</label>
      <input type="password" class="form-control" name="password" placeholder="Enter your password">
    </div>

    <!-- Confirm Password Input -->
    <div class="mb-2.5">
      <label for="confirmpassword" class="form-label">Confirm Password</label>
      <input type="password" class="form-control" name="confirmpassword" placeholder="Confirm your Password">
    </div>

    <div class="mb-2.5">
      <label for="phone" class="form-label">Contact Number:</label>
      <input type="tel" class="form-control" name="phone" placeholder="Enter valid Contact Number:">
    </div>

    <div class="mb-2.5">
      <label for="Shipping_address" class="form-label">Shipping Address</label>
      <input type="text" class="form-control" name="address" placeholder="Shipping Address">
    </div>

    <div class="mb-2.5">
      <label for="role" class="form-label">Role</label>
      <input type="text" class="form-control" name="role" value="customer" readonly>
    </div>

    <!-- If may account na ba siya  -->
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div class="form-check">
        <p>Already have an account? <a href="login.php"> Login here</a></p>
      </div>
    </div>

    <!-- Submit Button -->
    <div class="mb-2.5">
      <input type="submit" name="submit" id="submit" value="CONFIRM" class="btn btn-primary w-100">
    </div>
  </form>
</div>

  
</body>
<!-- Bootstrap JS -->
<script src="js/bootstrap.bundle.js"></script>
</html>
