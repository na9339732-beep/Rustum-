<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Check if admin is logged in
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

// Fetch teachers with department name
$sql = "
    SELECT t.*, d.department_name
    FROM teachers t
    LEFT JOIN departments d ON t.department_id = d.id
    ORDER BY t.teacher_name ASC
";
$result = mysqli_query($conn, $sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage Teachers — EMIS Portal</title>
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
            min-width: 700px;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
            vertical-align: middle;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .badge {
            background-color: #0d6efd;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
        }
        .btn {
            padding: 8px 16px;
            background: #0d6efd;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 14px;
            margin-right: 6px;
        }
        .btn:hover {
            background: #0b5ed7;
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .btn-sm {
            padding: 6px 12px;
            font-size: 13px;
        }
        .empty {
            color: #6c757d;
            font-style: italic;
            text-align: center;
            padding: 30px !important;
        }
    </style>
</head>
<body>

<div class="container">
    <?php include '../partials/sidebar.php'; ?>

    <main class="main">
        <h2>Manage Teachers</h2>

        <div class="card">
            <div class="header-actions">
                <h5 class="mb-0 fw-bold">Teachers Directory</h5>
                <a href="add_teacher.php" class="btn">
                    <i class="bi bi-plus-lg"></i> Add Teacher
                </a>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Subject</th>
                            <th>Department</th>
                            <th>Email</th>
                            <th style="width:160px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (mysqli_num_rows($result) > 0): ?>
                            <?php while ($teacher = mysqli_fetch_assoc($result)): ?>
                                <tr>
                                    <td><?= htmlspecialchars($teacher['teacher_name']) ?></td>
                                    <td><?= htmlspecialchars($teacher['subject'] ?? '—') ?></td>
                                    <td>
                                        <span class="badge">
                                            <?= htmlspecialchars($teacher['department_name'] ?? 'N/A') ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars($teacher['email']) ?></td>
                                    <td>
                                        <a href="edit_teacher.php?id=<?= $teacher['teacher_id'] ?>" class="btn btn-sm">
                                            Edit
                                        </a>
                                        <a href="delete_teacher.php?id=<?= $teacher['teacher_id'] ?>"
                                           class="btn btn-danger btn-sm"
                                           onclick="return confirm('Are you sure you want to delete this teacher?');">
                                            Delete
                                        </a>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="5" class="empty">
                                    No teachers found.
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</div>

</body>
</html>
