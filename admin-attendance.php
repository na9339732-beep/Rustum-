<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Check Admin
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin'){
    header("Location: ../login.php");
    exit;
}

// Fetch Attendance Records (JOIN with class table)
$sql = "
    SELECT 
        a.attendance_date,
        c.class_name,
        SUM(a.status = 'Present') AS present_count,
        SUM(a.status = 'Absent') AS absent_count,
        SUM(a.status = 'Leave')  AS leave_count
    FROM attendance a
    JOIN classes c ON c.class_id = a.class_id
    GROUP BY a.attendance_date, c.class_name
    ORDER BY a.attendance_date DESC
";


$result = mysqli_query($conn, $sql);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Manage Attendance — EMIS Portal</title>

  <!-- Bootstrap -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

  <!-- Custom CSS -->
  <link rel="stylesheet" href="../assets/styles.css">
  <link rel="stylesheet" href="../assets/sidebar.css">
</head>

<body>
<div class="container-fluid">
  <div class="row">

    <!-- Sidebar Desktop -->
    <div class="col-lg-auto d-none d-lg-block position-sticky top-0" style="height:100vh;overflow-y:auto;">
      <?php include '../partials/sidebar.php'; ?>
    </div>

    <!-- Main Content -->
    <main class="col p-4">

      <!-- Page Header -->
      <div class="d-flex justify-content-between align-items-center mb-4">
          <h3 class="fw-bold">Manage Attendance</h3>
          <div>
            <input type="text" class="form-control search rounded-4 shadow-sm d-inline-block" 
                   placeholder="Search..." style="max-width:300px;">
          </div>
      </div>

      <!-- Attendance Card -->
      <div class="card p-4 shadow-sm col-lg-10">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h5 class="fw-bold">Attendance Calendar</h5>
          <a class="btn btn-outline-primary" href="export_attendance.php">
            <i class="bi bi-file-earmark-arrow-down"></i> Export CSV
          </a>
        </div>

        <table class="table table-hover align-middle">
          <thead class="table-light">
            <tr>
              <th>Date</th>
              <th>Class</th>
              <th>Present</th>
              <th>Absent</th>
              <th>On Leave</th>
            </tr>
          </thead>
          <tbody>

            <?php if(mysqli_num_rows($result) > 0): ?>
              <?php while($row = mysqli_fetch_assoc($result)): ?>
                <tr>
                  <td><?= $row['attendance_date'] ?></td>
                  <td><?= htmlspecialchars($row['class_name']) ?></td>
                  <td><span class="badge bg-success"><?= $row['present_count'] ?></span></td>
                  <td><span class="badge bg-danger"><?= $row['absent_count'] ?></span></td>
                  <td><span class="badge bg-warning text-dark"><?= $row['leave_count'] ?></span></td>
                </tr>
              <?php endwhile; ?>
            <?php else: ?>
              <tr>
                <td colspan="5" class="text-center text-muted">No attendance records found.</td>
              </tr>
            <?php endif; ?>

          </tbody>
        </table>
      </div>

    </main>
  </div>
</div>

<!-- Mobile Sidebar -->
<div class="d-block d-md-none">
  <?php include '../partials/sidebar.php'; ?>
</div>

</body>
</html>
