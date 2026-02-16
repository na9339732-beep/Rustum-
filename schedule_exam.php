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

// Fetch active classes
$classes = mysqli_query($conn, "SELECT class_id, class_name FROM classes WHERE class_status='active' ORDER BY class_name ASC");
$success = $_GET['success'] ?? '';
$error = $_GET['error'] ?? '';
?>

<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Schedule Exam — EMIS Portal</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
</head>

<body>
<div class="container">
    <main class="col-auto col-md-8 main mx-auto">

      <div class="header mb-4">
        <h2 class="fw-bold">Schedule Exam</h2>
      </div>
        <?php if($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success); ?></div>
        <?php endif; ?>
        <?php if($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error); ?></div>
        <?php endif; ?>
      <!-- Card -->
      <div class="card p-4 shadow-sm">
        <h5 class="fw-bold mb-3">Exam Details</h5>

        <form action="save_exam.php" method="POST" class="row g-3">

          <div class="col-md-6">
            <label class="form-label fw-semibold">Exam Title</label>
            <input type="text" name="exam_title" class="form-control rounded-4" placeholder="e.g. Midterm Examination" required>
          </div>

          <div class="col-md-6">
            <label class="form-label fw-semibold">Class</label>
            <select name="class_id" class="form-select rounded-4" required>
              <option value="" disabled selected>Select Class</option>
              <?php while($c = mysqli_fetch_assoc($classes)): ?>
                  <option value="<?= $c['class_id']; ?>"><?= $c['class_name']; ?></option>
              <?php endwhile; ?>
            </select>
          </div>

          <div class="col-md-6">
            <label class="form-label fw-semibold">Start Date</label>
            <input type="date" name="start_date" class="form-control rounded-4" required>
          </div>

          <div class="col-md-6">
            <label class="form-label fw-semibold">End Date</label>
            <input type="date" name="end_date" class="form-control rounded-4" required>
          </div>

          <div class="col-12">
            <label class="form-label fw-semibold">Description (Optional)</label>
            <textarea name="description" class="form-control rounded-4" rows="3" placeholder="Notes about the exam..."></textarea>
          </div>

          <div class="col-12 d-flex justify-content-end gap-2 mt-3">
            <a href="admin-exams.php" class="btn btn-light rounded-4">Cancel</a>
            <button type="submit" class="btn btn-primary rounded-4">Save Exam</button>
          </div>
        </form>
      </div>

    </main>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
