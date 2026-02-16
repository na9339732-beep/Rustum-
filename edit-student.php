<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

// Check if admin is logged in
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

// Get student ID
$student_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($student_id <= 0) {
    die("Invalid student ID.");
}

// Fetch student info
$stmt = $conn->prepare("SELECT * FROM students WHERE student_id = ?");
$stmt->bind_param("i", $student_id);
$stmt->execute();
$result = $stmt->get_result();
$student = $result->fetch_assoc();
$stmt->close();

if (!$student) {
    die("Student not found.");
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $student_name = $_POST['student_name'] ?? '';
    $father_name  = $_POST['father_name'] ?? '';
    $email        = $_POST['email'] ?? '';
    $phone        = $_POST['phone'] ?? '';
    $class_id     = (int)($_POST['class_id'] ?? 0);
    $group_id     = $_POST['group_id'] ? (int)$_POST['group_id'] : null;
    $status       = $_POST['status'] ?? 'registered';
    $city         = $_POST['city'] ?? '';
    $state        = $_POST['state'] ?? '';

    // Validate status
    $allowed_status = ['registered', 'admitted', 'banned', 'suspended'];
    if (!in_array($status, $allowed_status)) {
        die("Invalid status selected.");
    }

    $stmt = $conn->prepare("
        UPDATE students SET 
            student_name = ?, 
            father_name = ?, 
            email = ?, 
            phone = ?, 
            class_id = ?, 
            group_id = ?,
            status = ?, 
            city = ?, 
            state = ?
        WHERE student_id = ?
    ");
    $stmt->bind_param("ssssiisssi", $student_name, $father_name, $email, $phone, $class_id, $group_id, $status, $city, $state, $student_id);
    $stmt->execute();
    $stmt->close();

    header("Location: admin-students.php");
    exit;
}

// Fetch classes for dropdown
$classes = $conn->query("SELECT class_id, class_name FROM classes ORDER BY class_name ASC")->fetch_all(MYSQLI_ASSOC);

// Fetch groups for dropdown
$groups = $conn->query("SELECT group_id, group_name FROM student_groups ORDER BY group_name ASC")->fetch_all(MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Edit Student — Admin</title>
<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
</head>
<body>
<div class="container">
    <?php include '../partials/sidebar.php'; ?>
    <main class="main">
        <h2>Edit Student</h2>
        <form method="POST">
            <div>
                <label>Student Name</label>
                <input type="text" name="student_name" value="<?= htmlspecialchars($student['student_name']) ?>" required>
            </div>
            <div>
                <label>Father Name</label>
                <input type="text" name="father_name" value="<?= htmlspecialchars($student['father_name']) ?>">
            </div>
            <div>
                <label>Email</label>
                <input type="email" name="email" value="<?= htmlspecialchars($student['email']) ?>">
            </div>
            <div>
                <label>Phone</label>
                <input type="text" name="phone" value="<?= htmlspecialchars($student['phone']) ?>">
            </div>
            <div>
                <label>Class</label>
                <select name="class_id" required>
                    <?php foreach ($classes as $class): ?>
                        <option value="<?= $class['class_id'] ?>" <?= $class['class_id'] == $student['class_id'] ? 'selected' : '' ?>>
                            <?= htmlspecialchars($class['class_name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label>Group</label>
                <select name="group_id">
                    <option value="">-- Select Group --</option>
                    <?php foreach ($groups as $g): ?>
                        <option value="<?= $g['group_id'] ?>" <?= $g['group_id'] == $student['group_id'] ? 'selected' : '' ?>>
                            <?= htmlspecialchars($g['group_name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label>Status</label>
                <select name="status">
                    <option value="registered" <?= $student['status']=='registered'?'selected':'' ?>>Registered</option>
                    <option value="admitted" <?= $student['status']=='admitted'?'selected':'' ?>>Admitted</option>
                    <option value="banned" <?= $student['status']=='banned'?'selected':'' ?>>Banned</option>
                    <option value="suspended" <?= $student['status']=='suspended'?'selected':'' ?>>Suspended</option>
                </select>
            </div>
            <div>
                <label>City</label>
                <input type="text" name="city" value="<?= htmlspecialchars($student['city']) ?>">
            </div>
            <div>
                <label>State</label>
                <input type="text" name="state" value="<?= htmlspecialchars($student['state']) ?>">
            </div>
            <div style="margin-top:10px;">
                <button type="submit" class="btn">Update Student</button>
                <a href="admin-students.php" class="btn">Cancel</a>
            </div>
        </form>
    </main>
</div>
</body>
</html>

