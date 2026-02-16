<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

// Restrict to Admin only
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

$departments = [];
$success = $error = null;
$newFileName = 'default.jpg';

// Fetch departments
$deptQuery = $conn->query("SELECT id, department_name FROM departments ORDER BY department_name");
if ($deptQuery) {
    while ($row = $deptQuery->fetch_assoc()) {
        $departments[] = $row;
    }
} else {
    die("Database Error: " . $conn->error);
}

// ================= FORM SUBMISSION =================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $teacher_name          = trim($_POST['teacher_name']);
    $email                 = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL) ? trim($_POST['email']) : '';
    $cnic                  = preg_replace('/\D/', '', $_POST['cnic']);
    $designation           = trim($_POST['designation']);
    $highest_qualification = trim($_POST['highest_qualification']);
    $bps                   = (int)$_POST['bps'];
    $department_id         = (int)$_POST['department'];
    $subject               = trim($_POST['subject']);
    $job_nature            = $_POST['job_nature'];
    $joining               = $_POST['joining'];
    $job_status            = $_POST['job_status'];

    if (!empty($_POST['email']) && !$email) {
        $error = "Please enter a valid email address.";
    }

    // === CHECK DUPLICATES ===
    if (!$error) {
        $checkTeacher = $conn->prepare("SELECT teacher_id FROM teachers WHERE cnic = ? OR email = ?");
        $checkUser    = $conn->prepare("SELECT user_id FROM users WHERE cnic = ? OR username = ? OR email = ?");

        $checkTeacher->bind_param("ss", $cnic, $email);
        $checkTeacher->execute();
        if ($checkTeacher->get_result()->num_rows > 0) {
            $error = "Teacher with this CNIC or Email already exists!";
        }

        $checkUser->bind_param("sss", $cnic, $cnic, $email);
        $checkUser->execute();
        if ($checkUser->get_result()->num_rows > 0) {
            $error = "User account with this CNIC or Email already exists!";
        }

        $checkTeacher->close();
        $checkUser->close();
    }

    // === PHOTO UPLOAD ===
    if (!$error && isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
        $ext = strtolower(pathinfo($_FILES['photo']['name'], PATHINFO_EXTENSION));
        $allowed = ['jpg','jpeg','png','gif'];

        if (in_array($ext, $allowed)) {
            $newFileName = uniqid('teacher_') . '.' . $ext;
            $uploadDir = __DIR__ . '/uploads/teachers/';
            if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
            move_uploaded_file($_FILES['photo']['tmp_name'], $uploadDir . $newFileName);
        } else {
            $error = "Only JPG, PNG & GIF images are allowed.";
        }
    }

    // === INSERT DATA ===
    if (!$error) {
        $conn->autocommit(false);

        try {
            $stmt1 = $conn->prepare("
                INSERT INTO teachers 
                (teacher_name, cnic, email, photo, designation, highest_qualification, bps, department_id, subject, job_nature, joining, job_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");

            $stmt1->bind_param(
                "ssssssisssss",
                $teacher_name,
                $cnic,
                $email,
                $newFileName,
                $designation,
                $highest_qualification,
                $bps,
                $department_id,
                $subject,
                $job_nature,
                $joining,
                $job_status
            );
            $stmt1->execute();

            $username = $email ?: $cnic;
            $password = password_hash($cnic, PASSWORD_DEFAULT);

            $stmt2 = $conn->prepare("
                INSERT INTO users (username, email, cnic, password, role, status)
                VALUES (?, ?, ?, ?, 'Teacher', 'active')
            ");
            $stmt2->bind_param("ssss", $username, $email, $cnic, $password);
            $stmt2->execute();

            $conn->commit();

            $success = "Teacher added successfully! <br>
                        <strong>Username:</strong> {$username}<br>
                        <strong>Password:</strong> {$cnic}";

        } catch (Exception $e) {
            $conn->rollback();
            $error = "Failed to add teacher.";
        }

        $conn->autocommit(true);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Add Teacher — EMIS</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link rel="stylesheet" href="../assets/sidebar.css">
<link rel="stylesheet" href="../assets/styles.css">

<style>
.photo-preview{
    max-width:150px;
    max-height:150px;
    border:2px dashed #ccc;
    border-radius:12px;
    object-fit:cover;
}
</style>
</head>

<body class="bg-light">

<div class="container-fluid">
  <div class="row flex-nowrap">

    <!-- SIDEBAR -->
    <aside class="col-auto col-md-3 col-xl-2 px-0 bg-white border-end min-vh-100">
      <?php include '../partials/sidebar.php'; ?>
    </aside>

    <!-- MAIN CONTENT -->
    <main class="col py-4 px-4 px-lg-5">

      <h3 class="fw-bold mb-4">Add New Teacher</h3>

      <?php if ($success): ?>
        <div class="alert alert-success alert-dismissible fade show">
          <?= $success ?>
          <button class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      <?php elseif ($error): ?>
        <div class="alert alert-danger alert-dismissible fade show">
          <?= htmlspecialchars($error) ?>
          <button class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      <?php endif; ?>

      <div class="card shadow-sm border-0">
        <div class="card-body p-4">

          <form method="post" enctype="multipart/form-data">
            <div class="row g-3">

              <div class="col-md-6">
                <label class="form-label">Teacher Name *</label>
                <input type="text" name="teacher_name" class="form-control" required>
              </div>

              <div class="col-md-6">
                <label class="form-label">Email</label>
                <input type="email" name="email" class="form-control">
              </div>

              <div class="col-md-6">
                <label class="form-label">CNIC *</label>
                <input type="text" name="cnic" class="form-control" required>
                <small class="text-muted">Default password</small>
              </div>

              <div class="col-md-6">
                <label class="form-label">Photo</label>
                <input type="file" name="photo" id="photoInput" class="form-control">
                <img id="preview" class="photo-preview d-none mt-2">
              </div>

              <div class="col-md-6">
                <label class="form-label">Designation *</label>
                <input type="text" name="designation" class="form-control" required>
              </div>

              <div class="col-md-6">
                <label class="form-label">Highest Qualification *</label>
                <input type="text" name="highest_qualification" class="form-control" required>
              </div>

              <div class="col-md-6">
                <label class="form-label">BPS *</label>
                <input type="number" name="bps" class="form-control" required>
              </div>

              <div class="col-md-6">
                <label class="form-label">Department *</label>
                <select name="department" class="form-select" required>
                  <option value="">Select</option>
                  <?php foreach($departments as $d): ?>
                    <option value="<?= $d['id'] ?>"><?= htmlspecialchars($d['department_name']) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="col-md-6">
                <label class="form-label">Subject *</label>
                <input type="text" name="subject" class="form-control" required>
              </div>

              <div class="col-md-6">
                <label class="form-label">Job Nature *</label>
                <select name="job_nature" class="form-select" required>
                  <option value="">Select</option>
                  <option>Permanent</option>
                  <option>Contract</option>
                </select>
              </div>

              <div class="col-md-6">
                <label class="form-label">Joining Date *</label>
                <input type="date" name="joining" class="form-control" required>
              </div>

              <div class="col-md-6">
                <label class="form-label">Job Status *</label>
                <select name="job_status" class="form-select" required>
                  <option>Active</option>
                  <option>Inactive</option>
                </select>
              </div>
            </div>

            <div class="mt-4">
              <button class="btn btn-primary btn-lg">Add Teacher</button>
              <a href="admin-teachers.php" class="btn btn-secondary btn-lg ms-2">Back</a>
            </div>

          </form>
        </div>
      </div>

    </main>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.getElementById('photoInput').addEventListener('change', e=>{
  const f=e.target.files[0],p=document.getElementById('preview');
  if(!f)return p.classList.add('d-none');
  const r=new FileReader();
  r.onload=()=>{p.src=r.result;p.classList.remove('d-none');};
  r.readAsDataURL(f);
});
</script>

</body>
</html>

