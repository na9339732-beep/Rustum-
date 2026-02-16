<?php
session_start();
include '../config/db.php';

// Only admin allowed
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin'){
    header("Location: ../login.php");
    exit;
}

// Validate ID
if(!isset($_GET['id']) || !is_numeric($_GET['id'])){
    die("Invalid Teacher ID.");
}

$teacher_id = $_GET['id'];

// Delete teacher
$stmt = $conn->prepare("DELETE FROM teachers WHERE teacher_id = ?");
$stmt->bind_param("i", $teacher_id);

if($stmt->execute()){
    header("Location: index.php?msg=Teacher+Deleted");
} else {
    echo "Error deleting teacher.";
}

$stmt->close();
$conn->close();
?>
