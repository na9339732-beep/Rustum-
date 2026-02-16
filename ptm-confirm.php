<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Parents') {
    header("Location: ../login.php");
    exit;
}

$child_id        = (int)($_POST['child_id'] ?? 0);
$teacher_id      = (int)($_POST['teacher_id'] ?? 0);
$availability_id = (int)($_POST['availability_id'] ?? 0);
$manual_date     = $_POST['manual_date'] ?? null; // Get the manual date from the form

if (!$child_id || !$teacher_id) {
    die("Invalid request");
}

$meeting_date = null;
$start_time = $end_time = null;

if ($availability_id > 0) {
    // Case 1: Parent picked a pre-defined slot
    $stmt = $conn->prepare("
        SELECT meeting_date, start_time, end_time 
        FROM teacher_availability 
        WHERE availability_id = ? 
          AND teacher_id = ? 
          AND status = 'Available'
    ");
    $stmt->bind_param("ii", $availability_id, $teacher_id);
    $stmt->execute();
    $slot = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$slot) {
        die("Selected slot is no longer available");
    }

    $meeting_date = $slot['meeting_date'];
    $start_time   = $slot['start_time'];
    $end_time     = $slot['end_time'];
    $status       = 'Confirmed';
} else {
    // Case 2: Parent used the calendar (Manual Request)
    if (empty($manual_date)) {
        die("Please select a meeting date.");
    }
    $meeting_date = $manual_date;
    $status       = 'Pending';
}

$booked_by = $_SESSION['user_id'];

// Prepare Insert
$stmt = $conn->prepare("
    INSERT INTO ptm_bookings 
    (child_id, teacher_id, availability_id, meeting_date, status, booked_by, created_at) 
    VALUES (?, ?, ?, ?, ?, ?, NOW())
");

// If availability_id is 0, we want to store NULL in the DB column
$avail_to_save = ($availability_id > 0) ? $availability_id : null;

$stmt->bind_param(
    "iiissi", 
    $child_id, 
    $teacher_id, 
    $avail_to_save, 
    $meeting_date, 
    $status, 
    $booked_by
);

if ($stmt->execute()) {
    $stmt->close();

    // Only update teacher_availability if an actual slot was used
    if ($availability_id > 0) {
        $update_stmt = $conn->prepare("
            UPDATE teacher_availability 
            SET status = 'Booked' 
            WHERE availability_id = ?
        ");
        $update_stmt->bind_param("i", $availability_id);
        $update_stmt->execute();
        $update_stmt->close();
    }

    header("Location: ptm-scheduler.php?msg=" . ($status === 'Pending' ? 'requested' : 'booked'));
    exit;
} else {
    die("Error saving booking: " . $conn->error);
}
