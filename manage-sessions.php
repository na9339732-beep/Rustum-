<?php
session_start();
include '../config/db.php';

/* --------------------
   AUTH CHECK
---------------------*/
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    header("Location: ../login.php");
    exit;
}

/* --------------------
   CSRF TOKEN
---------------------*/
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

$msg = "";

/* --------------------
   TOGGLE STATUS
---------------------*/
if (isset($_GET['toggle'], $_GET['csrf']) && $_GET['csrf'] === $csrf) {
    $id = (int) $_GET['toggle'];
    $conn->query("
        UPDATE sessions 
        SET status = IF(status='active','completed','active') 
        WHERE session_id = $id
    ");
    header("Location: manage-sessions.php");
    exit;
}

/* --------------------
   DELETE SESSION
---------------------*/
if (isset($_GET['delete'], $_GET['csrf']) && $_GET['csrf'] === $csrf) {
    $id = (int) $_GET['delete'];

    $chk = $conn->query("
        SELECT COUNT(*) AS total 
        FROM classes 
        WHERE session_id = $id
    ")->fetch_assoc();

    if ($chk['total'] > 0) {
        $msg = "<div class='alert alert-danger'>Batch linked with classes.</div>";
    } else {
        $conn->query("DELETE FROM sessions WHERE session_id = $id");
        $msg = "<div class='alert alert-success'>Batch deleted.</div>";
    }
}

/* --------------------
   UPDATE SESSION
---------------------*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['csrf'] ?? '') === $csrf) {

    $stmt = $conn->prepare("
        UPDATE sessions 
        SET session_name = ?, starting_date = ?, remarks = ? 
        WHERE session_id = ?
    ");

    $stmt->bind_param(
        "sssi",
        $_POST['session_name'],
        $_POST['starting_date'],
        $_POST['remarks'],
        $_POST['session_id']
    );

    $stmt->execute();
    $stmt->close();

    $msg = "<div class='alert alert-success'>Batch updated successfully.</div>";
}

/* --------------------
   FETCH DATA
---------------------*/
$sessions = $conn->query("
    SELECT * 
    FROM sessions 
    ORDER BY starting_date DESC
");
?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Manage Batches</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

  <link rel="stylesheet" href="../assets/styles.css">
  <link rel="stylesheet" href="../assets/sidebar.css">
</head>

<body class="bg-light">

<div class="d-flex">

    <!-- SIDEBAR -->
    <?php include '../partials/sidebar.php'; ?>

    <!-- MAIN CONTENT -->
    <main class="flex-grow-1 p-4">

        <div class="d-flex justify-content-between align-items-center mb-3">
            <h3 class="mb-0">Manage Academic Batches</h3>
            <a href="create_session.php" class="btn btn-primary">
                + New Batch
            </a>
        </div>

        <?= $msg ?>

        <div class="card shadow-sm">
            <div class="card-body table-responsive">

                <table class="table table-bordered align-middle mb-0">
                    <thead class="table-dark">
                        <tr>
                            <th>#</th>
                            <th>Batch</th>
                            <th>Start Date</th>
                            <th>Status</th>
                            <th>Remarks</th>
                            <th style="width:220px;">Actions</th>
                        </tr>
                    </thead>

                    <tbody>
                    <?php $i = 1; while ($row = $sessions->fetch_assoc()): ?>
                        <tr class="<?= $row['status'] === 'active' ? 'table-success' : '' ?>">
                            <td><?= $i++ ?></td>

                            <td><?= htmlspecialchars($row['session_name']) ?></td>

                            <td><?= $row['starting_date'] ?></td>

                            <td>
                                <span class="badge bg-<?= $row['status'] === 'active' ? 'success' : 'secondary' ?>">
                                    <?= ucfirst($row['status']) ?>
                                </span>
                            </td>

                            <td><?= htmlspecialchars($row['remarks'] ?? '') ?></td>

                            <td>
                                <a href="?toggle=<?= $row['session_id'] ?>&csrf=<?= $csrf ?>"
                                   class="btn btn-sm btn-warning">
                                    <?= $row['status'] === 'active' ? 'Complete' : 'Activate' ?>
                                </a>

                                <?php if ($row['status'] === 'active'): ?>
                                    <button
                                        class="btn btn-sm btn-info"
                                        onclick="openEditModal(
                                            <?= $row['session_id'] ?>,
                                            '<?= htmlspecialchars($row['session_name'], ENT_QUOTES) ?>',
                                            '<?= $row['starting_date'] ?>',
                                            '<?= htmlspecialchars($row['remarks'] ?? '', ENT_QUOTES) ?>'
                                        )">
                                        Edit
                                    </button>
                                <?php endif; ?>

                                <a href="?delete=<?= $row['session_id'] ?>&csrf=<?= $csrf ?>"
                                   class="btn btn-sm btn-danger"
                                   onclick="return confirm('Delete this Batch?')">
                                    Delete
                                </a>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                    </tbody>

                </table>

            </div>
        </div>

    </main>
</div>

<!-- EDIT MODAL -->
<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" class="modal-content">

            <div class="modal-header">
                <h5 class="modal-title">Edit Batch</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body">
                <input type="hidden" name="session_id" id="sid">
                <input type="hidden" name="csrf" value="<?= $csrf ?>">

                <div class="mb-3">
                    <label class="form-label">Batch Name</label>
                    <input type="text" name="session_name" id="sname" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Starting Date</label>
                    <input type="date" name="starting_date" id="sdate" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Remarks</label>
                    <textarea name="remarks" id="sremarks" class="form-control" rows="3"></textarea>
                </div>
            </div>

            <div class="modal-footer">
                <button class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button class="btn btn-success">Update</button>
            </div>

        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

<script>
function openEditModal(id, name, date, remarks) {
    document.getElementById('sid').value = id;
    document.getElementById('sname').value = name;
    document.getElementById('sdate').value = date;
    document.getElementById('sremarks').value = remarks;

    new bootstrap.Modal(document.getElementById('editModal')).show();
}
</script>

</body>
</html>
