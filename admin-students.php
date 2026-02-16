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

// Handle status update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['student_id'], $_POST['status'])) {
    $student_id = (int)$_POST['student_id'];
    $status = $_POST['status'];

    $allowed_status = ['registered', 'admitted', 'banned', 'suspended'];
    if (!in_array($status, $allowed_status)) {
        die("Invalid status selected.");
    }

    $stmt = $conn->prepare("UPDATE students SET status = ? WHERE student_id = ?");
    $stmt->bind_param("si", $status, $student_id);
    $stmt->execute();
    $stmt->close();

    header("Location: admin-students.php"); // reload page
    exit;
}

// Fetch all students
$students = [];
$res = $conn->query("SELECT student_id, student_name, father_name, class_id, status FROM students ORDER BY student_id ASC");
while ($row = $res->fetch_assoc()) {
    $students[] = $row;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Manage Students — Admin</title>
<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
table { width:100%; border-collapse: collapse; margin-top: 20px; }
th, td { padding:10px; border:1px solid #ccc; text-align:left; }
select { padding:5px; }
</style>
</head>
<body>
<div class="container">
    <?php include '../partials/sidebar.php'; ?>
    <main class="main">
        <h2>Manage Students</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Father Name</th>
                    <th>Class ID</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($students as $student): ?>
                <tr>
                    <td><?= htmlspecialchars($student['student_id']) ?></td>
                    <td><?= htmlspecialchars($student['student_name']) ?></td>
                    <td><?= htmlspecialchars($student['father_name']) ?></td>
                    <td><?= htmlspecialchars($student['class_id']) ?></td>
                    <td>
                        <form method="POST" style="display:flex;gap:5px;">
                            <input type="hidden" name="student_id" value="<?= $student['student_id'] ?>">
                            <select name="status" onchange="this.form.submit()">
                                <option value="registered" <?= $student['status']=='registered'?'selected':'' ?>>Registered</option>
                                <option value="admitted" <?= $student['status']=='admitted'?'selected':'' ?>>Admitted</option>
                                <option value="banned" <?= $student['status']=='banned'?'selected':'' ?>>Banned</option>
                                <option value="suspended" <?= $student['status']=='suspended'?'selected':'' ?>>Suspended</option>
                            </select>
                        </form>
                    </td>
                    <td>
                        <a href="edit-student.php?id=<?= $student['student_id'] ?>" class="btn">Edit</a>
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php if(empty($students)): ?>
                <tr><td colspan="6">No students found</td></tr>
                <?php endif; ?>
            </tbody>
        </table>
    </main>
</div>
</body>
</html>

