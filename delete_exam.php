<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Admin check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

// Validate exam_id
$exam_id = intval($_GET['exam_id'] ?? 0);
if ($exam_id <= 0) {
    die("Invalid Exam ID.");
}

// Delete exam_routine entries first
$stmt1 = $conn->prepare("DELETE FROM exam_routine WHERE exam_id = ?");
$stmt1->bind_param("i", $exam_id);
$stmt1->execute();

// Delete exam
$stmt2 = $conn->prepare("DELETE FROM exams WHERE exam_id = ?");
$stmt2->bind_param("i", $exam_id);

if ($stmt2->execute()) {
    $_SESSION['success'] = "Exam deleted successfully!";
} else {
    $_SESSION['errors'] = ["Error deleting exam: " . $stmt2->error];
}

header("Location: admin-exams.php");
exit;
?>
