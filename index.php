<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

// Check if parent is logged in
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Parents') {
    header("Location: ../login.php");
    exit;
}

$parent_id = $_SESSION['user_id'];
$_SESSION['user_id'] = $parent_id; // store in session

// Fetch children linked to this parent via CNIC
$children = [];
$stmt = $conn->prepare("
    SELECT s.student_id, s.student_name, c.class_name
    FROM students s
    JOIN classes c ON s.class_id = c.class_id
    JOIN users u ON u.cnic = s.father_cnic
    WHERE u.user_id = ?
      AND u.role = 'Parents'
");
$stmt->bind_param("i", $parent_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $children[$row['student_id']] = $row;
}
$stmt->close();

// Set default child in session if not set
if (!empty($children) && !isset($_SESSION['child_id'])) {
    $_SESSION['child_id'] = array_key_first($children);
}

// Fetch attendance percentage for each child
$attendance = [];
foreach ($children as $child_id => $child) {
    $stmt = $conn->prepare("
        SELECT 
            SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present_count,
            COUNT(*) AS total_count
        FROM attendance
        WHERE student_id = ?
    ");
    $stmt->bind_param("i", $child_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $attendance[$child_id] = ($row['total_count'] > 0) ? round(($row['present_count'] / $row['total_count']) * 100) : 'N/A';
    $stmt->close();
}

// Fetch latest 5 notifications
$notifications = [];
$res = $conn->query("SELECT message, created_at FROM notifications ORDER BY created_at DESC LIMIT 5");
while ($row = $res->fetch_assoc()) {
    $notifications[] = $row;
}

// Fetch next PTM for this parent's children
$next_ptm = null;
if (!empty($children)) {
    $child_ids = array_keys($children);
    $placeholders = implode(',', array_fill(0, count($child_ids), '?'));
    $types = str_repeat('i', count($child_ids) + 1);
    $stmt = $conn->prepare("
        SELECT pb.meeting_date, pb.status, t.teacher_name, s.student_name
        FROM ptm_bookings pb
        JOIN teachers t ON pb.teacher_id = t.teacher_id
        JOIN students s ON pb.child_id = s.student_id
        WHERE pb.child_id IN ($placeholders)
          AND pb.booked_by = ?
          AND pb.meeting_date >= CURDATE()
        ORDER BY pb.meeting_date ASC
        LIMIT 1
    ");
    $params = array_merge($child_ids, [$parent_id]);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $next_ptm = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Parent Dashboard — School Portal</title>
  <link rel="stylesheet" href="../assets/styles.css">
  <link rel="stylesheet" href="../assets/sidebar.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
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
      <div style="display:flex;gap:12px;align-items:center">
        <div style="font-size:20px;font-weight:700">Parent Dashboard</div>
     
      <div style="display:flex;gap:12px;align-items:flex-end">
        <div style="display:flex;gap:10px;align-items:flex-end">
          <div style="display:flex;flex-direction:column;align-items:flex-end">
            <div style="font-size:13px;font-weight:700"><?= htmlspecialchars($_SESSION['username'] ?? 'Parent') ?></div>
            <div style="font-size:12px;color:var(--muted)">Parent</div>
          </div>
        </div>
      </div>
    </div>
 </div>
    <div class="grid">
      <?php foreach ($children as $child_id => $child): ?>
      <div class="card">
        <div style="font-weight:700">Child</div>
        <div style="margin-top:8px;color:var(--muted)">
          <?= htmlspecialchars($child['student_name']) ?> — <?= htmlspecialchars($child['class_name']) ?>
        </div>
      </div>

      <div class="card">
        <div style="font-weight:700">Attendance</div>
        <div style="margin-top:8px;color:var(--muted)">
          <?= htmlspecialchars($child['student_name']) ?> — <?= htmlspecialchars($attendance[$child_id]) ?>% this term
        </div>
      </div>
      <?php endforeach; ?>

      <div class="card">
        <div style="font-weight:700">Next PTM</div>
        <?php if ($next_ptm): ?>
          <div style="margin-top:8px;color:green;font-weight:500">
            <?= htmlspecialchars($next_ptm['student_name']) ?> with <?= htmlspecialchars($next_ptm['teacher_name']) ?><br>
            on <?= date('d M Y', strtotime($next_ptm['meeting_date'])) ?> — <?= htmlspecialchars($next_ptm['status']) ?>
          </div>
        <?php else: ?>
          <a href="ptm-scheduler.php" style="text-decoration:none;color:inherit">
            <div style="margin-top:8px;color:var(--muted)">Book a slot</div>
          </a>
        <?php endif; ?>
      </div>
    </div>

    <div class="card">
      <div style="font-weight:700">Notifications</div>
      <ul style="margin-top:8px;color:var(--muted);padding-left:20px">
        <?php if ($notifications): ?>
          <?php foreach ($notifications as $note): ?>
            <li><?= htmlspecialchars($note['message']) ?> <small>(<?= date('d M Y', strtotime($note['created_at'])) ?>)</small></li>
          <?php endforeach; ?>
        <?php else: ?>
          <li>No notifications</li>
        <?php endif; ?>
      </ul>
    </div>
  </main>
</div>
</body>
</html>

