<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

/* ======================
   AUTH CHECK
====================== */
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit;
}

$conn = mysqli_connect($servername, $username, $password, $dbname);
if (!$conn) die("Database connection failed");

/* ======================
   FETCH RESULTS WITH STUDENT NAMES & SESSION
====================== */
$results = $conn->query("
    SELECT 
        r.id,
        r.student_id,
        s.student_name,
        r.subject,
        r.marks,
        r.grade,
        r.exam_term,
        r.session_id,
        se.session_name,
        r.created_at
    FROM results r
    LEFT JOIN students s ON r.student_id = s.student_id
    LEFT JOIN sessions se ON r.session_id = se.session_id
    ORDER BY s.student_name ASC, r.subject ASC
")->fetch_all(MYSQLI_ASSOC);

/* ======================
   CSV EXPORT
====================== */
if (isset($_POST['export_csv'])) {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="report_card.csv"');

    $output = fopen('php://output', 'w');
    fputcsv($output, ['Student', 'Subject', 'Marks', 'Grade', 'Exam Term', 'Session', 'Date']);

    foreach ($results as $r) {
        fputcsv($output, [
            $r['student_name'] ?? 'Unknown',
            $r['subject'],
            $r['marks'],
            $r['grade'],
            $r['exam_term'],
            $r['session_name'] ?? '-',
            $r['created_at']
        ]);
    }
    fclose($output);
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>View Results</title>
<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
<style>
body { font-family: Arial, sans-serif; margin:0; padding:0; }
.container { display: flex; gap: 20px; padding: 20px; }
.main { flex: 1; }
h2 { margin-bottom: 20px; }
table { width: 100%; border-collapse: collapse; }
th, td { border:1px solid #ccc; padding: 8px; text-align: center; }
th { background:#f4f4f4; }
button.export-btn { background:#4a63e7; color:#fff; border:none; padding:8px 15px; border-radius:5px; cursor:pointer; margin-bottom:15px; }
button.export-btn:hover { background:#3b50c4; }
</style>
</head>
<body>

<div class="container">

<!-- Sidebar -->
<div class="col-lg-3 d-none d-lg-block position-sticky top-0">
  <?php include '../partials/sidebar.php'; ?>
</div>

<!-- Main Content -->
<main class="main">
<h2> Student Results</h2>

<form method="post">
    <button type="submit" name="export_csv" class="export-btn">Generate Report Card (CSV)</button>
</form>

<table>
<tr>
<th>Student</th>
<th>Subject</th>
<th>Marks</th>
<th>Grade</th>
<th>Exam Term</th>
<th>Session</th>
<th>Date</th>
</tr>

<?php foreach($results as $r): ?>
<tr>
<td><?= htmlspecialchars($r['student_name'] ?? 'Unknown') ?></td>
<td><?= htmlspecialchars($r['subject']) ?></td>
<td><?= $r['marks'] ?></td>
<td><?= $r['grade'] ?></td>
<td><?= htmlspecialchars($r['exam_term']) ?></td>
<td><?= htmlspecialchars($r['session_name'] ?? '-') ?></td>
<td><?= $r['created_at'] ?></td>
</tr>
<?php endforeach; ?>

</table>
</main>

</div>
</body>
</html>

