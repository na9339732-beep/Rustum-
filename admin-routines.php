<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Check admin login
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

// Fetch routine
$sql = "
    SELECT
        tc.day,
        tc.start_time,
        tc.end_time,
        tc.subject,
        c.class_name,
        t.teacher_name
    FROM teacher_classes tc
    JOIN classes c ON tc.class_id = c.class_id
    JOIN teachers t ON tc.teacher_id = t.teacher_id
    WHERE tc.status = 'Active'
    ORDER BY tc.start_time
";
$result = mysqli_query($conn, $sql);

// Build routine array
$routine = [];
$days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
$time_slots = [];

while ($row = mysqli_fetch_assoc($result)) {
    $time_slot = date('H:i', strtotime($row['start_time'])) . " - " . date('H:i', strtotime($row['end_time']));
    if (!in_array($time_slot, $time_slots)) {
        $time_slots[] = $time_slot;
    }
    $routine[$time_slot][$row['day']] =
        htmlspecialchars($row['subject']) . "<br><small>(" . htmlspecialchars($row['teacher_name']) . ")</small>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Class Routine — EMIS Portal</title>
    <link rel="stylesheet" href="../assets/styles.css">
    <link rel="stylesheet" href="../assets/sidebar.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <style>
        .main {
            padding: 20px;
        }
        .card {
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 20px;
            margin-top: 20px;
        }
        h2 {
            margin-bottom: 20px;
            color: #333;
        }
        .header-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        table {
            width: 100%;
            min-width: 800px;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            border: 1px solid #ddd;
            text-align: center;
            vertical-align: middle;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .time-col {
            background-color: #f1f3f5;
            font-weight: bold;
            min-width: 120px;
            position: sticky;
            left: 0;
            z-index: 1;
        }
        .empty {
            color: #6c757d;
            font-style: italic;
        }
        .btn {
            padding: 8px 16px;
            background: #0d6efd;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 14px;
        }
        .btn:hover {
            background: #0b5ed7;
        }
    </style>
</head>
<body>

<div class="container">
    <?php include '../partials/sidebar.php'; ?>

    <main class="main">
        <h2>Class Timings & Routines</h2>

        <div class="card">
            <div class="header-actions">
                <h5 class="mb-0 fw-bold">Weekly Class Routine</h5>
                <a href="create_routine.php" class="btn">
                    <i class="bi bi-plus-lg"></i> Create Routine
                </a>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th class="time-col">Time Slot</th>
                            <?php foreach ($days as $day): ?>
                                <th><?= htmlspecialchars($day) ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($time_slots)): ?>
                            <tr>
                                <td colspan="6" class="text-center py-4 empty">
                                    No routines found.
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($time_slots as $time): ?>
                                <tr>
                                    <td class="time-col"><?= htmlspecialchars($time) ?></td>
                                    <?php foreach ($days as $day): ?>
                                        <td>
                                            <?= $routine[$time][$day] ?? '<span class="empty">—</span>' ?>
                                        </td>
                                    <?php endforeach; ?>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</div>

</body>
</html>
