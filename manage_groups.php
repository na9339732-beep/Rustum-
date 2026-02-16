<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

include '../config/db.php';

/* ===== AUTH CHECK ===== */
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

/* ===== ADD GROUP ===== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $group_name = trim($_POST['group_name'] ?? '');

    if ($group_name !== '') {
        $stmt = $conn->prepare("
            INSERT INTO student_groups (group_name)
            VALUES (?)
        ");
        $stmt->bind_param("s", $group_name);
        $stmt->execute();
        $stmt->close();
    }
    header("Location: manage_groups.php");
    exit;
}

/* ===== DELETE GROUP ===== */
if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];

    $stmt = $conn->prepare("
        DELETE FROM student_groups
        WHERE group_id = ?
    ");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();

    header("Location: manage_groups.php");
    exit;
}

/* ===== FETCH GROUPS ===== */
$groups = $conn->query("
    SELECT * FROM student_groups
    ORDER BY group_name
")->fetch_all(MYSQLI_ASSOC);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Manage Student Groups</title>
<meta name="viewport" content="width=device-width,initial-scale=1">

<link rel="stylesheet" href="../assets/styles.css">
<link rel="stylesheet" href="../assets/sidebar.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

<style>
.card{padding:20px;background:#fff;border-radius:10px}
.table th,.table td{padding:10px;border:1px solid #ddd}
</style>
</head>

<body>
<div class="container">

<!-- Sidebar -->
<div class="col-lg-3 d-none d-lg-block position-sticky top-0">
  <?php include '../partials/sidebar.php'; ?>
</div>

<main class="main col-lg-9">

<h4 class="mb-3">Manage Student Groups</h4>

<!-- ADD GROUP -->
<div class="card mb-4">
<h6>Add New Group</h6>
<form method="post" class="d-flex gap-2">
<input type="text" name="group_name" class="form-control search" placeholder="e.g. ICS, Pre-Engineering" required>
<button class="btn btn-primary">Add</button>
</form>
</div>

<!-- GROUP LIST -->
<div class="card">
<h6>Existing Groups</h6>

<table class="table">
<tr>
<th>#</th>
<th>Group Name</th>
<th>Action</th>
</tr>

<?php if($groups): $i=1; foreach($groups as $g): ?>
<tr>
<td><?= $i++ ?></td>
<td><?= htmlspecialchars($g['group_name']) ?></td>
<td>
<a href="?delete=<?= $g['group_id'] ?>"
   onclick="return confirm('Delete this group?')"
   class="text-danger">
<i class="bi bi-trash"></i>
</a>
</td>
</tr>
<?php endforeach; else: ?>
<tr><td colspan="3">No groups added</td></tr>
<?php endif; ?>

</table>
</div>

</main>
</div>
</body>
</html>

