<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

$conn = mysqli_connect($servername, $username, $password, $dbname);
if (!$conn) die("Database connection failed.");

// Check if parent is logged in
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Parents') {
    header("Location: ../login.php");
    exit;
}

// Get child_id from GET or default to first child
$parent_cnic = $_SESSION['cnic'] ?? '';
$child_id = (int)($_GET['child_id'] ?? 0);

// Fetch children linked to this parent
$children = [];
$stmt = $conn->prepare("SELECT student_id, student_name, class_id FROM students WHERE father_cnic = ?");
$stmt->bind_param("s", $parent_cnic);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $children[$row['student_id']] = $row;
}
$stmt->close();

// If no child_id passed, pick the first child
if (!$child_id && count($children) > 0) {
    $child_id = array_key_first($children);
}

$child = $children[$child_id] ?? null;
$childName = $child['student_name'] ?? 'Unknown Child';
$class_id = $child['class_id'] ?? 0;

// Fetch subjects for the class
$subjects = [];
$stmt = $conn->prepare("SELECT subject_name FROM subjects WHERE class_id = ?");
$stmt->bind_param("i", $class_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $subjects[] = $row['subject_name'];
}
$stmt->close();

// Fetch marks for this child
$marks = [];
$stmt = $conn->prepare("SELECT subject, marks FROM results WHERE student_id = ?");
$stmt->bind_param("i", $child_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $marks[$row['subject']] = $row['marks'];
}
$stmt->close();

// Calculate attendance % for the class
$total_days_stmt = $conn->prepare("SELECT COUNT(*) as total FROM attendance WHERE student_id = ? AND class_id = ?");
$total_days_stmt->bind_param("ii", $child_id, $class_id);
$total_days_stmt->execute();
$total_days_res = $total_days_stmt->get_result()->fetch_assoc();
$total_days = $total_days_res['total'] ?? 0;
$total_days_stmt->close();

$present_days_stmt = $conn->prepare("SELECT COUNT(*) as present FROM attendance WHERE student_id = ? AND class_id = ? AND status='Present'");
$present_days_stmt->bind_param("ii", $child_id, $class_id);
$present_days_stmt->execute();
$present_days_res = $present_days_stmt->get_result()->fetch_assoc();
$present_days = $present_days_res['present'] ?? 0;
$present_days_stmt->close();

$attendance_percent = $total_days > 0 ? round(($present_days/$total_days)*100, 2) : 'N/A';

// Prepare records array for table
$records = [];
foreach ($subjects as $sub) {
    $records[] = [
        'subject_name' => $sub,
        'marks' => $marks[$sub] ?? 'N/A',
        'attendance' => $attendance_percent
    ];
}
?>

<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Child Marks & Attendance — EMIS Portal</title>
<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<style>
  .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; }
  .header-left { display:flex; gap:12px; align-items:center; font-size:20px; font-weight:700; }
  .header-right { display:flex; flex-direction:column; align-items:flex-end; font-size:12px; color:var(--muted); }
  .table { width:100%; border-collapse:collapse; }
  .table th, .table td { border:1px solid #ddd; padding:8px; text-align:left; }
  .table th { background-color:#f2f2f2; }
</style>
</head>
<body>
<div class="container">
  <div class="col-lg-2 d-none d-lg-block bg-white glass shadow-sm position-sticky top-0">
    <div class="pt-4 px-lg-2 pt-5">
      <?php include '../partials/sidebar.php'; ?>
    </div>
  </div>

  <main class="main">
    <div class="header">
      <div class="header-left">
        Child Marks & Attendance / <?= htmlspecialchars($childName) ?>
      </div>
      <div class="header-right">
        <div><?= htmlspecialchars($_SESSION['username'] ?? 'Parent') ?></div>
        <div>Parent</div>
      </div>
    </div>

    <div class="card">
      <div style="font-weight:700; margin-bottom:12px"><?= htmlspecialchars($childName) ?> — Summary</div>
      <table class="table">
        <thead>
        <tr>
          <th>Subject</th>
          <th>Marks</th>
          <th>Attendance</th>
        </tr>
        </thead>
        <tbody>
        <?php if ($records): ?>
          <?php foreach ($records as $rec): ?>
            <tr>
              <td><?= htmlspecialchars($rec['subject_name']) ?></td>
              <td><?= htmlspecialchars($rec['marks']) ?></td>
              <td><?= htmlspecialchars($rec['attendance']) ?>%</td>
            </tr>
          <?php endforeach; ?>
        <?php else: ?>
          <tr><td colspan="3">No records found</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </main>
</div>
</body>
</html>
