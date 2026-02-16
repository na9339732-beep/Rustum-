<?php
session_start();
include '../config/db.php';

if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin'){
    header("Location: ../login.php");
    exit;
}

if($_SERVER['REQUEST_METHOD'] === 'POST'){
    $exam_title = $_POST['exam_title'];
    $class_id   = $_POST['class_id'];
    $start_date = $_POST['start_date'];
    $end_date   = $_POST['end_date'];
    $description= $_POST['description'] ?? '';

    // Validate dates
    if($start_date > $end_date){
        header("Location: schedule_exam.php?error=Start date cannot be after end date");
        exit;
    }

    $stmt = $conn->prepare("INSERT INTO exams (exam_title, class_id, start_date, end_date, description) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sisss", $exam_title, $class_id, $start_date, $end_date, $description);
    if($stmt->execute()){
        header("Location: schedule_exam.php?success=Exam scheduled successfully!");
        exit;
    } else {
        header("Location: schedule_exam.php?error=Failed to schedule exam");
        exit;
    }
}
?>
