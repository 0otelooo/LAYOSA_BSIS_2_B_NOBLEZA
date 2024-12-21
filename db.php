<?php
$host = 'localhost'; // Database host
$dbname = 'nyro'; // Replace with your database name
$username = 'root'; // MySQL username
$password = ''; // MySQL password (default is empty for XAMPP)

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}
?>