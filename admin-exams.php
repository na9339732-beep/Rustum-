<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Check admin login
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin'){
    header("Location: ../login.php");
    exit;
}

// Fetch exams with class names
$sql = "SELECT e.exam_id, e.exam_title, e.start_date, e.end_date, c.class_name 
        FROM exams e 
        JOIN classes c ON e.class_id = c.class_id 
        ORDER BY e.start_date ASC";

$exams = mysqli_query($conn, $sql);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Exam Scheduler — School Portal</title>

  <!-- Bootstrap -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

  <link rel="stylesheet" href="../assets/styles.css">
  <link rel="stylesheet" href="../assets/sidebar.css">

  <style>
    /* Sidebar fixed for desktop */
    .sidebar-fixed {
      height: 100vh;
      overflow-y: auto;
      position: sticky;
      top: 0;
    }
    /* Table wrapper for scroll on small screens */
    .table-responsive-custom {
      overflow-x: auto;
    }
    /* Header search box */
    .header-search {
      max-width: 300px;
    }
    /* Responsive flex for header */
    @media (max-width: 991px) {
      .header-flex {
        flex-direction: column;
        gap: 1rem;
      }
    }
  </style>
</head>

<body class="bg-light">

<div class="d-flex vh-100">
<?php include '../partials/sidebar.php'; ?>

<main class="flex-grow-1 p-4">

    <!-- Header -->
    <div class="d-flex justify-content-between align-items-center header-flex mb-4">
      <h3 class="fw-bold">Exam Scheduler</h3>
      <div class="d-flex align-items-center gap-3">
        <input type="text" class="form-control rounded-4 shadow-sm header-search" placeholder="Search exams...">
        <div class="text-end">
          <div class="fw-bold small"><?= htmlspecialchars($_SESSION['username'] ?? 'Admin'); ?></div>
          <small class="text-muted">Administrator</small>
        </div>
      </div>
    </div>

    <!-- Exam Card -->
    <div class="card p-3 shadow-sm">

      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="fw-bold mb-0">Exams & Date Sheets</h5>
        <a class="btn btn-primary" href="./schedule_exam.php">
          <i class="bi bi-plus-lg"></i> Schedule Exam
        </a>
      </div>

      <div class="table-responsive-custom">
        <table class="table table-striped align-middle">
          <thead class="table-dark">
            <tr>
              <th>Exam</th>
              <th>Class</th>
              <th>Start Date</th>
              <th>End Date</th>
              <th class="text-center">Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php if(mysqli_num_rows($exams) > 0): ?>
              <?php while($row = mysqli_fetch_assoc($exams)): ?>
                <tr>
                  <td><?= htmlspecialchars($row['exam_title']); ?></td>
                  <td><?= htmlspecialchars($row['class_name']); ?></td>
                  <td><?= date('d M Y', strtotime($row['start_date'])); ?></td>
                  <td><?= date('d M Y', strtotime($row['end_date'])); ?></td>
                  <td class="text-center">
                    <a class="btn btn-sm btn-outline-primary" href="./view_datesheet.php?exam_id=<?= $row['exam_id']; ?>">View</a>
                    <a class="btn btn-sm btn-outline-warning" href="./edit_exam.php?exam_id=<?= $row['exam_id']; ?>">Edit</a>
                    <a class="btn btn-sm btn-outline-danger" href="./delete_exam.php?exam_id=<?= $row['exam_id']; ?>" onclick="return confirm('Are you sure?')">Delete</a>
                  </td>
                </tr>
              <?php endwhile; ?>
            <?php else: ?>
              <tr>
                <td colspan="5" class="text-center text-muted">No exams scheduled yet.</td>
              </tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>

    </div>

  </main>
</div>

<!-- MOBILE SIDEBAR -->
<div class="d-block d-lg-none">
  <?php include '../partials/sidebar.php'; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

