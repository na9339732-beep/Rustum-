<?php
include '../config/db.php';

$msg = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['session_name'];
    $starting_date = $_POST['starting_date'];
    $remarks = $_POST['remarks'];

    if (!empty($name) && !empty($starting_date)) {
        $stmt = $conn->prepare("
            INSERT INTO sessions (session_name, starting_date, remarks) 
            VALUES (?, ?, ?)
        ");
        $stmt->bind_param("sss", $name, $starting_date, $remarks);

        if ($stmt->execute()) {
            $msg = "<div class='alert alert-success'>Session Created Successfully!</div>";
        } else {
            $msg = "<div class='alert alert-danger'>Error: Unable to create session.</div>";
        }
    } else {
        $msg = "<div class='alert alert-warning'>Please fill required fields.</div>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Create Session</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<div class="container mt-5">
    <div class="card shadow">
        <div class="card-header bg-primary text-white">
            <h4>Create New Session</h4>
        </div>
        <div class="card-body">

            <?= $msg ?>

            <form method="POST">
                <div class="mb-3">
                    <label class="form-label">Session Name</label>
                    <input type="text" name="session_name" class="form-control" placeholder="e.g., 2024-2025" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Starting Date</label>
                    <input type="date" name="starting_date" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Remarks (Optional)</label>
                    <textarea name="remarks" class="form-control" rows="2"></textarea>
                </div>

                <button class="btn btn-success">Create Session</button>
            </form>

        </div>
    </div>
</div>

</body>
</html>
