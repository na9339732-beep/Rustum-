<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include '../config/db.php';

// Redirect if not parent
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Parents') {
    header("Location: ../login.php");
    exit;
}

$fcnic = $_SESSION['cnic'] ?? '';
$selected_child_id = (int)($_GET['child_id'] ?? 0);

/* =====================
   Ajax: fetch available slots for a teacher
===================== */
if (isset($_GET['ajax']) && $_GET['ajax'] === 'slots' && isset($_GET['teacher_id'])) {
    $teacher_id = (int)$_GET['teacher_id'];

    $stmt = $conn->prepare("
        SELECT availability_id, meeting_date, start_time, end_time
        FROM teacher_availability
        WHERE teacher_id = ?
          AND status = 'Available'
          AND meeting_date >= CURDATE()
        ORDER BY meeting_date, start_time
    ");
    $stmt->bind_param("i", $teacher_id);
    $stmt->execute();
    $res = $stmt->get_result();

    $slots = [];
    while ($row = $res->fetch_assoc()) {
        $slots[] = $row;
    }

    header('Content-Type: application/json');
    echo json_encode($slots);
    exit;
}

/* =====================
   Fetch all children of this parent
===================== */
$children = [];
$stmt = $conn->prepare("SELECT student_id, student_name, class_id FROM students WHERE father_cnic = ?");
$stmt->bind_param("s", $fcnic);
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    $children[$row['student_id']] = $row;
}
$stmt->close();

/* =====================
   Selection Logic
===================== */
$no_children = empty($children);
if (!$no_children) {
    if (!$selected_child_id || !isset($children[$selected_child_id])) {
        $selected_child_id = array_key_first($children);
    }

    $child = $children[$selected_child_id];
    $child_name = $child['student_name'];
    $class_id = $child['class_id'];

    // Get session_id
    $stmt = $conn->prepare("SELECT session_id FROM classes WHERE class_id = ?");
    $stmt->bind_param("i", $class_id);
    $stmt->execute();
    $class_row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    $session_id = $class_row['session_id'] ?? 1;

    // Fetch teachers
    $stmt = $conn->prepare("
        SELECT DISTINCT t.teacher_id, t.teacher_name, tc.subject
        FROM teacher_classes tc
        JOIN teachers t ON tc.teacher_id = t.teacher_id
        WHERE tc.class_id = ?
          AND tc.session_id = ?
        ORDER BY t.teacher_name, tc.subject
    ");
    $stmt->bind_param("ii", $class_id, $session_id);
    $stmt->execute();
    $teacher_result = $stmt->get_result();

    $teachers = [];
    while ($row = $teacher_result->fetch_assoc()) {
        $teachers[$row['teacher_id']] = $row['teacher_name'] . " (" . $row['subject'] . ")";
    }
    $stmt->close();
}
?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>PTM Scheduler — EMIS Portal</title>
    <link rel="stylesheet" href="../assets/styles.css">
    <link rel="stylesheet" href="../assets/sidebar.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <style>
        .child-selector { margin: 16px 0; }
        .child-btn { 
            padding: 10px 16px; 
            margin-right: 8px; 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            background: #f8f9fa;
            text-decoration: none;
            color: #333;
            display: inline-block;
        }
        .child-btn.active { 
            background: #007bff; 
            color: white; 
            border-color: #007bff;
        }
        .form-grid {
            display: grid;
            gap: 16px;
            grid-template-columns: 1fr 1fr auto;
            align-items: end;
        }
        @media (max-width: 768px) {
            .form-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="container">
    <?php include '../partials/sidebar.php'; ?>

    <main class="main">
        <div class="header">
            <div style="font-size:20px;font-weight:700">Parent-Teacher Meeting</div>
            <div style="font-size:13px;font-weight:700"><?= htmlspecialchars($_SESSION['username'] ?? 'Parent') ?> (Parent)</div>
        </div>

        <?php if ($no_children): ?>
            <div class="card">
                <div class="alert alert-info">
                    <strong>No Children Found</strong><br>
                    Your account is not linked to any student.
                </div>
            </div>
        <?php else: ?>
            <div class="card">
                <div style="font-weight:700;margin-bottom:12px">Select Child</div>
                <div class="child-selector">
                    <?php foreach ($children as $id => $c): ?>
                        <a href="?child_id=<?= $id ?>" class="child-btn <?= $id == $selected_child_id ? 'active' : '' ?>">
                            <?= htmlspecialchars($c['student_name']) ?>
                        </a>
                    <?php endforeach; ?>
                </div>
                <div style="color:var(--muted);font-size:14px;margin-top:8px">
                    Currently viewing: <strong><?= htmlspecialchars($child_name) ?></strong>
                </div>
            </div>

            <div class="card">
                <div style="font-weight:700;margin-bottom:12px">Book Meeting with Teacher</div>

                <?php if (empty($teachers)): ?>
                    <div class="alert alert-warning">
                        No teachers assigned to <?= htmlspecialchars($child_name) ?>'s class.
                    </div>
                <?php else: ?>
                    <form action="ptm-confirm.php" method="POST" style="margin-top:16px">
                        <input type="hidden" name="child_id" value="<?= $selected_child_id ?>">

                        <div class="form-grid">
                            <div>
                                <label style="font-weight:600">Teacher</label>
                                <select id="teacherSelect" name="teacher_id" required style="width:100%;padding:12px;border-radius:8px;border:1px solid #ddd">
                                    <option value="">-- Select Teacher --</option>
                                    <?php foreach ($teachers as $id => $name): ?>
                                        <option value="<?= $id ?>"><?= htmlspecialchars($name) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div id="slotWrapper">
                                <label style="font-weight:600">Available Slot</label>
                                <select id="slotSelect" name="availability_id" style="width:100%;padding:12px;border-radius:8px;border:1px solid #ddd">
                                    <option value="">-- Select Slot --</option>
                                </select>
                            </div>

                            <div id="manualDateContainer" style="display:none;">
                                <label style="font-weight:600">Suggest a Date</label>
                                <input type="date" name="manual_date" id="manualDate" min="<?= date('Y-m-d') ?>" style="width:100%;padding:12px;border-radius:8px;border:1px solid #ddd">
                            </div>

                            <div>
                                <button type="submit" class="btn">Book Meeting</button>
                            </div>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </main>
</div>

<script>
document.getElementById('teacherSelect')?.addEventListener('change', function () {
    const teacherId = this.value;
    const slotSelect = document.getElementById('slotSelect');
    const slotWrapper = document.getElementById('slotWrapper');
    const manualDateContainer = document.getElementById('manualDateContainer');
    const manualDateInput = document.getElementById('manualDate');

    // Reset View
    slotSelect.innerHTML = '<option>Loading...</option>';
    slotWrapper.style.display = 'block';
    manualDateContainer.style.display = 'none';
    manualDateInput.required = false;

    if (!teacherId) {
        slotSelect.innerHTML = '<option value="">-- Select Slot --</option>';
        return;
    }

    fetch(`ptm-scheduler.php?ajax=slots&teacher_id=${teacherId}`)
        .then(res => res.json())
        .then(data => {
            if (data.length === 0) {
                // No slots -> Show Calendar
                slotWrapper.style.display = 'none';
                manualDateContainer.style.display = 'block';
                manualDateInput.required = true;
                slotSelect.value = ""; // Clear slot selection
            } else {
                // Slots available -> Show Dropdown
                slotWrapper.style.display = 'block';
                manualDateContainer.style.display = 'none';
                manualDateInput.required = false;
                manualDateInput.value = ""; // Clear manual date

                slotSelect.innerHTML = '<option value="">-- Select Slot --</option>';
                data.forEach(slot => {
                    const option = document.createElement('option');
                    option.value = slot.availability_id;
                    option.textContent = `${slot.meeting_date} | ${slot.start_time} - ${slot.end_time}`;
                    slotSelect.appendChild(option);
                });
            }
        })
        .catch(err => {
            console.error("Fetch error:", err);
            slotSelect.innerHTML = '<option value="">Error loading slots</option>';
        });
});
</script>
</body>
</html>
