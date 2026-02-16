<?php
include '../config/db.php'; // DB connect

$msg = "";

// Fetch sessions for dropdown
$sessions = $conn->query("SELECT * FROM sessions WHERE status='active'");

// If form submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $class_name = $_POST['class_name'];
    $class_short = $_POST['class_short'];
    $session_id = $_POST['session_id'];

    if (!empty($class_name) && !empty($class_short)) {

        $stmt = $conn->prepare("
            INSERT INTO classes (class_name, class_short, session_id) 
            VALUES (?, ?, ?)
        ");
        $stmt->bind_param("ssi", $class_name, $class_short, $session_id);

        if ($stmt->execute()) {
            $msg = "<div class='alert alert-success'>Class Created Successfully!</div>";
        } else {
            $msg = "<div class='alert alert-danger'>Error creating class.</div>";
        }

    } else {
        $msg = "<div class='alert alert-warning'>Please fill all required fields.</div>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Create Class</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<div class="container mt-5">

    <div class="card shadow">
        <div class="card-header bg-primary text-white">
            <h4>Create New Class</h4>
        </div>

        <div class="card-body">

            <?= $msg ?>

            <form method="POST">

                <div class="mb-3">
                    <label class="form-label">Class Name</label>
                    <input type="text" name="class_name" class="form-control" placeholder="e.g., 10th Grade" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Class Short Name</label>
                    <input type="text" name="class_short" class="form-control" placeholder="e.g., 10th" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Select Session</label>
                    <select name="session_id" class="form-control" required>
                        <option value="">-- Select Session --</option>
                        <?php while ($s = $sessions->fetch_assoc()): ?>
                            <option value="<?= $s['session_id'] ?>">
                                <?= $s['session_name'] ?>
                            </option>
                        <?php endwhile; ?>
                    </select>
                </div>

                <button class="btn btn-success">Create Class</button>

            </form>

        </div>
    </div>

</div>

</body>
</html>
