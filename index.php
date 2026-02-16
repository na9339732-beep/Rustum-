<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

include '../config/db.php';

// ====== FETCH COUNTS ======
$studentsCount = $conn->query("SELECT COUNT(*) AS total FROM students")->fetch_assoc()['total'];
$teachersCount = $conn->query("SELECT COUNT(*) AS total FROM teachers")->fetch_assoc()['total'];
$classesCount  = $conn->query("SELECT COUNT(*) AS total FROM classes")->fetch_assoc()['total'];

// ====== RECENT ACTIVITY (Last 5 registered users) ======
$recentActivity = $conn->query("
    SELECT username, creation_date
    FROM users
    ORDER BY creation_date DESC
    LIMIT 5
");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Dashboard — EMIS Portal</title>
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
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #fff;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card small {
            color: #6c757d;
            font-size: 0.9em;
        }
        .stat-card h2 {
            margin: 10px 0 0;
            font-size: 2.5rem;
            color: #0d6efd;
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
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .btn {
            padding: 10px 18px;
            background: #0d6efd;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn:hover {
            background: #0b5ed7;
        }
        .btn-outline {
            background: transparent;
            color: #0d6efd;
            border: 1px solid #0d6efd;
        }
        .btn-outline:hover {
            background: #0d6efd;
            color: white;
        }
        .btn-sm {
            padding: 8px 14px;
            font-size: 13px;
        }
        .quick-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }
        .empty {
            text-align: center;
            color: #6c757d;
            padding: 20px;
            font-style: italic;
        }
    </style>
</head>
<body>

<div class="container">
    <?php include '../partials/sidebar.php'; ?>

    <main class="main">
        <h2>Admin Dashboard</h2>

        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <small>Total Students</small>
                <h2><?= $studentsCount ?></h2>
            </div>
            <div class="stat-card">
                <small>Total Teachers</small>
                <h2><?= $teachersCount ?></h2>
            </div>
            <div class="stat-card">
                <small>Total Classes</small>
                <h2><?= $classesCount ?></h2>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="card">
            <div class="header-actions">
                <h5 class="mb-0 fw-bold">Recent User Registrations</h5>
                <a href="admin-students.php" class="btn btn-sm">Manage Students</a>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Registration Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($recentActivity->num_rows > 0): ?>
                            <?php while ($row = $recentActivity->fetch_assoc()): ?>
                                <tr>
                                    <td><?= htmlspecialchars($row['username']) ?></td>
                                    <td><?= htmlspecialchars($row['creation_date']) ?></td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="2" class="empty">No recent registrations</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="card">
            <h5 class="fw-bold mb-3">Quick Actions</h5>
            <div class="quick-actions">
                <a href="add_teacher.php" class="btn">
                    <i class="bi bi-person-plus"></i> Add Teacher
                </a>
                <a href="create_session.php" class="btn btn-outline">
                    <i class="bi bi-calendar-plus"></i> Create Session
                </a>
                <a href="create_class.php" class="btn btn-outline">
                    <i class="bi bi-building"></i> Create Class
                </a>
                <a href="manage_groups.php" class="btn btn-outline">
                    <i class="bi bi-book"></i> Manage Groups
                </a>
                  <a href="result.php" class="btn btn-outline">
                    <i class="bi bi-trophy"></i> View Results
                </a>
                <a href="view-ptm.php" class="btn btn-outline">
                    <i class="bi bi-calendar"></i> View PTMS
                </a>
                <a href="add_notification.php" class="btn btn-outline">
                    <i class="bi bi-bell"></i> Create Notification
                </a>
            </div>
        </div>
    </main>
</div>

</body>
</html>
