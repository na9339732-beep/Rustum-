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

$parent_cnic = $_SESSION['cnic'] ?? '';
$child_id = (int)($_GET['child_id'] ?? 0);

// Fetch children linked to this parent
$children = [];
$stmt = $conn->prepare("SELECT student_id, student_name, class_id FROM students WHERE father_cnic = ? ORDER BY student_name");
$stmt->bind_param("s", $parent_cnic);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $children[$row['student_id']] = $row;
}
$stmt->close();

// If no child_id, redirect to first child
if (!$child_id && !empty($children)) {
    $child_id = array_key_first($children);
    header("Location: ?child_id=$child_id");
    exit;
}

$child = $children[$child_id] ?? null;
if (!$child) {
    die("No child found or access denied.");
}

$childName = $child['student_name'];
$class_id = $child['class_id'];

// Fetch routine
$stmt = $conn->prepare("
    SELECT subject, day, start_time, end_time
    FROM teacher_classes
    WHERE class_id = ? AND status = 'Active'
    ORDER BY FIELD(day, 'Monday','Tuesday','Wednesday','Thursday','Friday'), start_time
");
$stmt->bind_param("i", $class_id);
$stmt->execute();
$res = $stmt->get_result();

$routine = [];
$time_slots = [];

while ($row = $res->fetch_assoc()) {
    $day = $row['day'];
    $slot = date('h:i A', strtotime($row['start_time'])) . ' - ' . date('h:i A', strtotime($row['end_time']));
    $time_slots[$slot] = true;
    $routine[$slot][$day] = $row['subject'];
}
$stmt->close();

// Fixed day order
$days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
$time_slots = array_keys($time_slots);
sort($time_slots);
?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Class Routine — <?= htmlspecialchars($childName) ?> | EMIS Portal</title>
    <link rel="stylesheet" href="../assets/styles.css">
    <link rel="stylesheet" href="../assets/sidebar.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
</head>
<body>
<div class="container">
    <!-- Desktop Sidebar -->
    <div class="col-lg-2 d-none d-lg-block bg-white glass shadow-sm position-sticky top-0" style="height: 100vh;">
        <div class="pt-4 px-lg-2 pt-5">
            <?php include '../partials/sidebar.php'; ?>
        </div>
    </div>

    <main class="main">
        <div class="header">
            <!-- Page Title + Child Name -->
            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <h1 style="margin: 0; font-size: 20px; font-weight: 700;">Class Routine</h1>
                <span style="color: var(--muted);">/ <?= htmlspecialchars($childName) ?></span>
            </div>

            <!-- Child Selector + User Info (in one row) -->
            <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-top: 16px;">
                <!-- Child Selector (only if multiple children) -->
                <?php if (count($children) > 1): ?>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="color: var(--muted); font-size: 14px;">Viewing:</span>
                        <select onchange="window.location = '?child_id=' + this.value" 
                                style="padding: 8px 14px; border-radius: 12px; border: 1px solid #e0e0e0; background: var(--card); font-size: 14px;">
                            <?php foreach ($children as $id => $c): ?>
                                <option value="<?= $id ?>" <?= $id == $child_id ? 'selected' : '' ?>>
                                    <?= htmlspecialchars($c['student_name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div style="margin-left: auto; display: flex; align-items: center; gap: 10px;">
                    <div style="text-align: right;">
                        <div style="font-size: 13px; font-weight: 700;"><?= htmlspecialchars($_SESSION['username']) ?></div>
                        <div style="font-size: 12px; color: var(--muted);">Parent</div>
                    </div>
                </div>
                <?php endif; ?>

                <!-- User Info (aligned to the right) -->

            </div>
        </div>

        <!-- Routine Card -->
        <div class="card">
            <h3 style="margin: 0 0 20px 0; font-weight: 700;">Weekly Class Routine</h3>

            <?php if (!empty($time_slots)): ?>
                <div class="table-wrapper">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 160px;">Time</th>
                                <?php foreach ($days as $day): ?>
                                    <th><?= htmlspecialchars($day) ?></th>
                                <?php endforeach; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($time_slots as $slot): ?>
                                <tr>
                                    <td><strong><?= htmlspecialchars($slot) ?></strong></td>
                                    <?php foreach ($days as $day): ?>
                                        <td><?= htmlspecialchars($routine[$slot][$day] ?? '-') ?></td>
                                    <?php endforeach; ?>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div style="text-align: center; padding: 60px 20px; color: var(--muted);">
                    <i class="bi bi-calendar-x" style="font-size: 64px; opacity: 0.4; margin-bottom: 16px;"></i>
                    <p style="font-size: 16px; margin: 0;">No class routine has been assigned yet for this class.</p>
                </div>
            <?php endif; ?>
        </div>
    </main>
</div>
</body>
</html>
