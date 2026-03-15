<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

include '../config/db.php';

/* ======================
   AUTH CHECK
====================== */
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Student') {
    header("Location: ../login.php");
    exit;
}

/* ======================
   FETCH STUDENT ID
   (assuming user_id is linked in students table)
====================== */
$user_id = $_SESSION['user_id'];

$stmt = $conn->prepare("
    SELECT student_id, student_name
    FROM students
    WHERE user_id = ?
    LIMIT 1
");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$student = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$student) {
    die("Student record not found.");
}

$student_id   = (int)$student['student_id'];
$student_name = $student['student_name'];

/* ======================
   FILTER (MONTH)
====================== */
$month = $_GET['month'] ?? date('Y-m');

/* ======================
   FETCH ATTENDANCE
====================== */
$stmt = $conn->prepare("
    SELECT 
        a.attendance_date,
        a.status,
        c.class_name
    FROM attendance a
    JOIN classes c ON a.class_id = c.class_id
    WHERE a.student_id = ?
      AND DATE_FORMAT(a.attendance_date, '%Y-%m') = ?
    ORDER BY a.attendance_date DESC
");
$stmt->bind_param("is", $student_id, $month);
$stmt->execute();
$attendance = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

/* ======================
   STATS
====================== */
$stats = ['Present'=>0,'Absent'=>0,'Leave'=>0];
foreach ($attendance as $row) {
    if (isset($stats[$row['status']])) {
        $stats[$row['status']]++;
    }
}
?>

<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>My Attendance</title>
<meta name="viewport" content="width=device-width, initial-scale=1">

<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
.badge-present{background:#28a745}
.badge-absent{background:#dc3545}
.badge-leave{background:#ffc107;color:#000}
</style>
</head>

<body>
<div class="container-fluid">
<div class="row">

<!-- SIDEBAR -->
<div class="col-lg-3 d-none d-lg-block bg-white shadow-sm position-sticky top-0">
    <?php include '../partials/sidebar.php'; ?>
</div>

<!-- MAIN -->
<main class="col-lg-9 p-4">

<div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="fw-bold">My Attendance</h4>
    <div class="text-end">
        <strong><?= htmlspecialchars($student_name) ?></strong><br>
        <small class="text-muted">Student</small>
    </div>
</div>

<!-- FILTER -->
<form method="get" class="mb-3">
    <label class="form-label fw-bold">Select Month</label>
    <input type="month" name="month" value="<?= htmlspecialchars($month) ?>" class="form-control" style="max-width:200px">
</form>

<!-- STATS -->
<div class="row mb-4">
    <div class="col-md-4">
        <div class="card p-3 text-center">
            <h6>Present</h6>
            <h4 class="text-success"><?= $stats['Present'] ?></h4>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card p-3 text-center">
            <h6>Absent</h6>
            <h4 class="text-danger"><?= $stats['Absent'] ?></h4>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card p-3 text-center">
            <h6>Leave</h6>
            <h4 class="text-warning"><?= $stats['Leave'] ?></h4>
        </div>
    </div>
</div>

<!-- TABLE -->
<div class="card shadow-sm">
<div class="card-body">

<table class="table table-bordered align-middle">
<thead class="table-light">
<tr>
    <th>Date</th>
    <th>Class</th>
    <th>Status</th>
</tr>
</thead>
<tbody>

<?php if ($attendance): foreach ($attendance as $row): ?>
<tr>
    <td><?= date('d M Y', strtotime($row['attendance_date'])) ?></td>
    <td><?= htmlspecialchars($row['class_name']) ?></td>
    <td>
        <?php if($row['status']==='Present'): ?>
            <span class="badge badge-present">Present</span>
        <?php elseif($row['status']==='Absent'): ?>
            <span class="badge badge-absent">Absent</span>
        <?php else: ?>
            <span class="badge badge-leave">Leave</span>
        <?php endif; ?>
    </td>
</tr>
<?php endforeach; else: ?>
<tr>
    <td colspan="3" class="text-center text-muted">No attendance found</td>
</tr>
<?php endif; ?>

</tbody>
</table>

</div>
</div>

</main>
</div>
</div>

</body>
</html>

