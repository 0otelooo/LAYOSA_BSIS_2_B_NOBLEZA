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
