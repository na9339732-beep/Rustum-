<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

// Admin check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $exam_id      = intval($_POST['exam_id'] ?? 0);
    $class_id     = intval($_POST['class_id'] ?? 0);
    $subject_name = trim($_POST['subject_name'] ?? '');
    $exam_date    = $_POST['exam_date'] ?? '';
    $start_time   = $_POST['start_time'] ?? '';
    $end_time     = $_POST['end_time'] ?? '';

    $errors = [];

    // Validation
    if ($exam_id <= 0) $errors[] = "Invalid exam.";
    if ($class_id <= 0) $errors[] = "Invalid class.";
    if (empty($subject_name)) $errors[] = "Subject name is required.";
    if (empty($exam_date)) $errors[] = "Exam date is required.";
    if (empty($start_time) || empty($end_time)) $errors[] = "Start and end time are required.";

    // Duration check: 1–4 hours
    $duration = (strtotime($end_time) - strtotime($start_time)) / 3600;
    if ($duration < 1 || $duration > 4) $errors[] = "Duration must be between 1 hour and 4 hours.";

    if (empty($errors)) {
        // Ensure subject exists
        $stmt = $conn->prepare("SELECT subject_id FROM subjects WHERE subject_name = ? AND class_id = ?");
        $stmt->bind_param("si", $subject_name, $class_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $subject_id = $result->fetch_assoc()['subject_id'];
        } else {
            // Insert new subject
            $status = 'active';
            $stmt_insert = $conn->prepare("INSERT INTO subjects (subject_name, class_id, status) VALUES (?, ?, ?)");
            $stmt_insert->bind_param("sis", $subject_name, $class_id, $status);
            $stmt_insert->execute();
            $subject_id = $stmt_insert->insert_id;
        }

        // Insert into exam routine
        $stmt_routine = $conn->prepare("INSERT INTO exam_routine (exam_id, subject_id, exam_date, start_time, end_time) VALUES (?, ?, ?, ?, ?)");
        $stmt_routine->bind_param("iisss", $exam_id, $subject_id, $exam_date, $start_time, $end_time);

        if ($stmt_routine->execute()) {
            $_SESSION['success'] = "Subject added to exam successfully!";
        } else {
            $_SESSION['errors'] = ["Database error: " . $stmt_routine->error];
        }
    } else {
        $_SESSION['errors'] = $errors;
    }

    header("Location: view_datesheet.php?exam_id=" . $exam_id);
    exit;
}

// Get exam_id from URL
$exam_id = intval($_GET['exam_id'] ?? 0);
if ($exam_id <= 0) {
    die("Invalid Exam ID.");
}

// Fetch exam details
$exam_query = $conn->prepare("SELECT e.exam_id, e.exam_title, e.class_id, c.class_name, e.start_date, e.end_date 
                              FROM exams e
                              JOIN classes c ON c.class_id = e.class_id
                              WHERE e.exam_id = ?");
$exam_query->bind_param("i", $exam_id);
$exam_query->execute();
$exam = $exam_query->get_result()->fetch_assoc();
if (!$exam) {
    die("Exam not found.");
}

// Fetch subjects in this exam
$subjects_query = $conn->prepare("SELECT er.id as routine_id, s.subject_name, er.exam_date, er.start_time, er.end_time
                                  FROM exam_routine er
                                  JOIN subjects s ON s.subject_id = er.subject_id
                                  WHERE er.exam_id = ?
                                  ORDER BY er.exam_date ASC, er.start_time ASC");
$subjects_query->bind_param("i", $exam_id);
$subjects_query->execute();
$subjects_result = $subjects_query->get_result();
?>


<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($exam['exam_title']) ?> — Date Sheet</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
</head>
<body>
<div class="container mt-4">

    <!-- Sidebar for desktop -->
    <div class="col-lg-auto d-none d-lg-block position-sticky top-0">
        <?php include '../partials/sidebar.php'; ?>
    </div>

    <main class="main">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div>
                <h3><?= htmlspecialchars($exam['exam_title']) ?></h3>
                <small class="text-muted"><?= htmlspecialchars($exam['class_name']) ?> — <?= $exam['start_date'] ?> to <?= $exam['end_date'] ?></small>
            </div>
            <button class="btn btn-primary rounded-4" data-bs-toggle="collapse" data-bs-target="#addSubjectForm">
                <i class="bi bi-plus-circle"></i> Add Subject
            </button>
        </div>

        <!-- Success/Error Messages -->
        <?php if(isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?= $_SESSION['success']; unset($_SESSION['success']); ?></div>
        <?php endif; ?>
        <?php if(isset($_SESSION['errors'])): ?>
            <?php foreach($_SESSION['errors'] as $error): ?>
                <div class="alert alert-danger"><?= $error; ?></div>
            <?php endforeach; unset($_SESSION['errors']); ?>
        <?php endif; ?>

        <!-- Add Subject Form -->
        <div class="collapse mb-4" id="addSubjectForm">
            <div class="card card-body">
                <form action="" method="POST">
                    <input type="hidden" name="exam_id" value="<?= $exam['exam_id'] ?>">
                    <input type="hidden" name="class_id" value="<?= $exam['class_id'] ?>">

                    <div class="mb-3">
                        <label>Subject Name</label>
                        <input type="text" name="subject_name" class="form-control" required placeholder="e.g. Mathematics">
                    </div>

                    <div class="mb-3">
                        <label>Exam Date</label>
                        <input type="date" name="exam_date" class="form-control" required min="<?= $exam['start_date'] ?>" max="<?= $exam['end_date'] ?>">
                    </div>

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label>Start Time</label>
                            <input type="time" name="start_time" class="form-control" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label>End Time</label>
                            <input type="time" name="end_time" class="form-control" required>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-success w-100">Add Subject</button>
                </form>
            </div>
        </div>

        <!-- Subjects Table -->
        <div class="card p-4 shadow-sm">
            <table class="table align-middle table-striped">
                <thead class="table-light">
                    <tr>
                        <th>Subject</th>
                        <th>Date</th>
                        <th>Start Time</th>
                        <th>End Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if($subjects_result->num_rows > 0): ?>
                        <?php while($row = $subjects_result->fetch_assoc()): ?>
                            <tr>
                                <td><?= htmlspecialchars($row['subject_name']) ?></td>
                                <td><?= $row['exam_date'] ?></td>
                                <td><?= date("h:i A", strtotime($row['start_time'])) ?></td>
                                <td><?= date("h:i A", strtotime($row['end_time'])) ?></td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="4" class="text-center text-muted">No subjects scheduled yet.</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>

    <!-- Mobile Sidebar -->
    <div class="d-block d-md-none">
        <?php include '../partials/sidebar.php'; ?>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
