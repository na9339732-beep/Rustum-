<?php
session_start();
include '../config/db.php';

// Fetch classes
$classes = mysqli_query($conn, "SELECT class_id, class_name FROM classes WHERE class_status='active' ORDER BY class_name ASC");

// Fetch teachers
$teachers = mysqli_query($conn, "SELECT teacher_id, teacher_name FROM teachers WHERE job_status='Active' ORDER BY teacher_name ASC");

// Retrieve messages
$errors = $_SESSION['errors'] ?? [];
$success = $_SESSION['success'] ?? '';
unset($_SESSION['errors'], $_SESSION['success']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Add Subject</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <h2 class="mb-4">Add New Subject</h2>

    <?php if(!empty($errors)): ?>
        <div class="alert alert-danger">
            <ul>
                <?php foreach($errors as $err): ?>
                    <li><?= htmlspecialchars($err) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <?php if($success): ?>
        <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>

    <form action="save_subject.php" method="POST">
        <div class="mb-3">
            <label class="form-label">Subject Name</label>
            <input type="text" name="subject_name" class="form-control" required>
        </div>

        <div class="mb-3">
            <label class="form-label">Class</label>
            <select name="class_id" class="form-select" required>
                <option value="">Select Class</option>
                <?php while($c = mysqli_fetch_assoc($classes)): ?>
                    <option value="<?= $c['class_id'] ?>"><?= htmlspecialchars($c['class_name']) ?></option>
                <?php endwhile; ?>
            </select>
        </div>

        <div class="mb-3">
            <label class="form-label">Teacher</label>
            <select name="teacher_id" class="form-select" required>
                <option value="">Select Teacher</option>
                <?php while($t = mysqli_fetch_assoc($teachers)): ?>
                    <option value="<?= $t['teacher_id'] ?>"><?= htmlspecialchars($t['teacher_name']) ?></option>
                <?php endwhile; ?>
            </select>
        </div>

        <div class="mb-3">
            <label class="form-label">Status</label>
            <select name="status" class="form-select">
                <option value="active" selected>Active</option>
                <option value="inactive">Inactive</option>
            </select>
        </div>

        <button type="submit" class="btn btn-primary">Add Subject</button>
    </form>
</div>
</body>
</html>
