<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Only Admin can access
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin'){
    header("Location: ../login.php");
    exit;
}

if($_SERVER['REQUEST_METHOD'] == 'POST') {

    // Collect and sanitize inputs
    $subject_name = trim(mysqli_real_escape_string($conn, $_POST['subject_name'] ?? ''));
    $class_id    = intval($_POST['class_id'] ?? 0);
    $teacher_id  = intval($_POST['teacher_id'] ?? 0);
    $status      = $_POST['status'] ?? 'active';

    $errors = [];

    // Validation
    if(empty($subject_name)) $errors[] = "Subject name is required.";
    if($class_id <= 0) $errors[] = "Please select a valid class.";
    if($teacher_id <= 0) $errors[] = "Please select a valid teacher.";
    if(!in_array($status, ['active','inactive'])) $errors[] = "Invalid status selected.";

    // Check for duplicate
    $check_sql = "SELECT * FROM subjects WHERE subject_name=? AND class_id=?";
    $stmt_check = $conn->prepare($check_sql);
    $stmt_check->bind_param("si", $subject_name, $class_id);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();
    if($result_check->num_rows > 0) $errors[] = "This subject already exists for the selected class.";

    if(empty($errors)) {
        // Insert
        $insert_sql = "INSERT INTO subjects (subject_name, class_id, teacher_id, status) VALUES (?, ?, ?, ?)";
        $stmt = $conn->prepare($insert_sql);
        $stmt->bind_param("siis", $subject_name, $class_id, $teacher_id, $status);

        if($stmt->execute()) {
            $_SESSION['success'] = "Subject created successfully!";
        } else {
            $_SESSION['errors'] = ["Database error: " . $stmt->error];
        }
    } else {
        $_SESSION['errors'] = $errors;
    }

    header("Location: add_subject.php");
    exit;

} else {
    header("Location: add_subject.php");
    exit;
}
?>
