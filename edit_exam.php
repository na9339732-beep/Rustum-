<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
include '../config/db.php';

// Admin check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

// Validate exam_id
$exam_id = intval($_GET['exam_id'] ?? 0);
if ($exam_id <= 0) die("Invalid Exam ID.");

// Fetch exam details
$stmt = $conn->prepare("SELECT * FROM exams WHERE exam_id = ?");
$stmt->bind_param("i", $exam_id);
$stmt->execute();
$exam = $stmt->get_result()->fetch_assoc();

if (!$exam) die("Exam not found.");

// Fetch all classes
$classes = mysqli_query($conn, "SELECT * FROM classes ORDER BY class_name ASC");

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $title = trim($_POST['exam_title']);
    $class_id = intval($_POST['class_id']);
    $start_date = $_POST['start_date'];
    $end_date   = $_POST['end_date'];

    if (empty($title)) {
        $error = "Exam title is required.";
    } elseif ($class_id <= 0) {
        $error = "Invalid class.";
    } elseif ($start_date > $end_date) {
        $error = "Start date cannot be after end date.";
    } else {
        // Update exam
        $update = $conn->prepare("UPDATE exams SET exam_title=?, class_id=?, start_date=?, end_date=? WHERE exam_id=?");
        $update->bind_param("sissi", $title, $class_id, $start_date, $end_date, $exam_id);

        if ($update->execute()) {
            $_SESSION['success'] = "Exam updated successfully!";
            header("Location: admin-exams.php");
            exit;
        } else {
            $error = "Database error: " . $update->error;
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Edit Exam</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">

  <h3 class="mb-3">Edit Exam</h3>

  <?php if (!empty($error)): ?>
    <div class="alert alert-danger"><?= $error ?></div>
  <?php endif; ?>

  <form method="POST">
    <div class="mb-3">
      <label class="form-label">Exam Title</label>
      <input type="text" name="exam_title" class="form-control" required value="<?= htmlspecialchars($exam['exam_title']) ?>">
    </div>

    <div class="mb-3">
      <label class="form-label">Class</label>
      <select name="class_id" class="form-select" required>
        <?php while ($class = mysqli_fetch_assoc($classes)): ?>
          <option value="<?= $class['class_id'] ?>" 
            <?= $exam['class_id'] == $class['class_id'] ? 'selected' : '' ?>>
              <?= htmlspecialchars($class['class_name']) ?>
          </option>
        <?php endwhile; ?>
      </select>
    </div>

    <div class="mb-3">
      <label class="form-label">Start Date</label>
      <input type="date" name="start_date" class="form-control" required value="<?= $exam['start_date'] ?>">
    </div>

    <div class="mb-3">
      <label class="form-label">End Date</label>
      <input type="date" name="end_date" class="form-control" required value="<?= $exam['end_date'] ?>">
    </div>

    <button class="btn btn-success">Save Changes</button>
    <a href="admin-exams.php" class="btn btn-secondary">Cancel</a>
  </form>

</div>
</body>
</html>
