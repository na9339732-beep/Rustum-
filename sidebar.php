<?php
if (!isset($_SESSION)) { session_start(); }
$role = $_SESSION['role'] ?? '';
$current_page = basename($_SERVER['PHP_SELF']); // to highlight active page
?>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<!-- Desktop Sidebar -->
<div class="sidebar vh-100 d-none d-lg-block position-sticky top-0 col-lg-3" id="sidebar" style="height:100vh;">
    <div class="brand mb-5 p-4 text-center">
        <div class="logo mb-2"><img src="../assets/images/logo.png" width="60" alt="Logo"></div>
        <div class="fw-bold fs-4 text-primary">EMIS</div>
    </div>

    <nav class="nav vh-100 bg-light flex-column px-3">
        <!-- Common for All -->
        <a href="index.php" class="nav-link <?= $current_page == 'index.php' ? 'active' : '' ?>">
            <i class="bi bi-house-door"></i> Dashboard
        </a>

        <!-- Admin & SuperAdmin -->
        <?php if ($role === 'Admin' || $role === 'SuperAdmin'): ?>
            <a href="admin-teachers.php" class="nav-link <?= strpos($current_page, 'admin-teachers') !== false ? 'active' : '' ?>">
                <i class="bi bi-person-badge"></i> Manage Teachers
            </a>
            <a href="admin-students.php" class="nav-link <?= strpos($current_page, 'admin-students') !== false ? 'active' : '' ?>">
                <i class="bi bi-people"></i> Manage Students
            </a>
            <a href="admin-routines.php" class="nav-link <?= strpos($current_page, 'admin-routines') !== false ? 'active' : '' ?>">
                <i class="bi bi-calendar3"></i> Routines & Timings
            </a>
            <a href="admin-exams.php" class="nav-link <?= strpos($current_page, 'admin-exams') !== false ? 'active' : '' ?>">
                <i class="bi bi-file-earmark-text"></i> Exam Scheduler
            </a>
            <a href="admin-attendance.php" class="nav-link <?= strpos($current_page, 'admin-attendance') !== false ? 'active' : '' ?>">
                <i class="bi bi-check2-square"></i> Attendance
            </a>
            <a href="manage-sessions.php" class="nav-link <?= strpos($current_page, 'manage-sessions') !== false ? 'active' : '' ?>">
                <i class="bi bi-calendar-check"></i> Manage Batches
            </a>
            <a href="manage-classes.php" class="nav-link <?= strpos($current_page, 'manage-classes') !== false ? 'active' : '' ?>">
                <i class="bi bi-building"></i> Manage Classes
            </a>
        <?php endif; ?>

        <!-- Teacher Only -->
        <?php if ($role === 'Teacher'): ?>
            <a href="teacher-materials.php" class="nav-link <?= strpos($current_page, 'teacher-materials') !== false ? 'active' : '' ?>">
                <i class="bi bi-collection"></i> Manage Materials
            </a>
            <a href="teacher-attendance.php" class="nav-link <?= strpos($current_page, 'teacher-attendance') !== false ? 'active' : '' ?>">
                <i class="bi bi-check2-circle"></i> Take Attendance
            </a>
             <a href="manage_results.php" class="nav-link <?= strpos($current_page, 'manage_results') !== false ? 'active' : '' ?>">
                <i class="bi bi-trophy"></i> Manage Results
            </a>
            <a href="teacher-students.php" class="nav-link <?= strpos($current_page, 'teacher-students') !== false ? 'active' : '' ?>">
                <i class="bi bi-people"></i> My Students
            </a>
        <?php endif; ?>

        <!-- Student Only -->
        <?php if ($role === 'Student'): ?>
            <a href="student-materials.php" class="nav-link <?= strpos($current_page, 'student-materials') !== false ? 'active' : '' ?>">
                <i class="bi bi-book"></i> My Materials
            </a>
            <a href="student-results.php" class="nav-link <?= strpos($current_page, 'student-results') !== false ? 'active' : '' ?>">
                <i class="bi bi-trophy"></i> My Results
            </a>
            <a href="student-routine.php" class="nav-link <?= strpos($current_page, 'student-routine') !== false ? 'active' : '' ?>">
                <i class="bi bi-calendar-week"></i> My Routine
            </a>
            <a href="attendance.php" class="nav-link <?= strpos($current_page, 'attendance') !== false ? 'active' : '' ?>">
                <i class="bi bi-check2-square"></i> Attendance
            </a>
        <?php endif; ?>

        <!-- Parent Only -->
        <?php if ($role === 'Parents'): ?>
            <a href="parent-child-report.php" class="nav-link <?= strpos($current_page, 'parent-child-report') !== false ? 'active' : '' ?>">
                <i class="bi bi-file-earmark-text"></i> Child Report
            </a>
            <a href="parent-routine.php" class="nav-link <?= strpos($current_page, 'parent-routine') !== false ? 'active' : '' ?>">
                <i class="bi bi-calendar3"></i> Class Routine
            </a>
            <a href="ptm-scheduler.php" class="nav-link <?= strpos($current_page, 'ptm-scheduler') !== false ? 'active' : '' ?>">
                <i class="bi bi-calendar-plus"></i> PTM Schedule
            </a>
        <?php endif; ?>

        <!-- Logout -->
        <hr class="my-4">
        <a href="../logout.php" class="nav-link text-danger">
            <i class="bi bi-box-arrow-right"></i> Logout
        </a>
    </nav>
</div>

<!-- Mobile Bottom Navigation -->
<div class="mobile-bottom-nav d-lg-none fixed-bottom bg-white border-top shadow-lg">
    <div class="d-flex justify-content-around align-items-center h-100 flex-wrap">

        <!-- Admin & SuperAdmin -->
        <?php if ($role === 'Admin' ): ?>
            <a href="index.php" class="nav-icon <?= $current_page == 'index.php' ? 'active' : '' ?>"><i class="bi bi-house-door fs-4"></i><div>Home</div></a>
            <a href="admin-students.php" class="nav-icon"><i class="bi bi-people fs-4"></i><div>Students</div></a>
            <a href="admin-teachers.php" class="nav-icon"><i class="bi bi-person-badge fs-4"></i><div>Teachers</div></a>
            <a href="admin-routines.php" class="nav-icon"><i class="bi bi-calendar3 fs-4"></i><div>Routines</div></a>
            <a href="admin-exams.php" class="nav-icon"><i class="bi bi-file-earmark-text fs-4"></i><div>Exams</div></a>
            <a href="admin-attendance.php" class="nav-icon"><i class="bi bi-check2-square fs-4"></i><div>Attendance</div></a>
            <a href="manage-sessions.php" class="nav-icon"><i class="bi bi-calendar-check fs-4"></i><div>Batches</div></a>
            <a href="manage-classes.php" class="nav-icon"><i class="bi bi-building fs-4"></i><div>Classes</div></a>
        <?php elseif ($role === 'Teacher'): ?>
            <a href="teacher-classes.php" class="nav-icon"><i class="bi bi-collection fs-4"></i><div>Classes</div></a>
            <a href="teacher-attendance.php" class="nav-icon"><i class="bi bi-check2-circle fs-4"></i><div>Attendance</div></a>
            <a href="teacher-routine.php" class="nav-icon"><i class="bi bi-calendar-week fs-4"></i><div>Routine</div></a>
             <a href="manage_results.php" class="nav-icon"><i class="bi trophy fs-4"></i><div>Results</div></a>
        <?php elseif ($role === 'Student'): ?>
            <a href="student-materials.php" class="nav-icon"><i class="bi bi-book fs-4"></i><div>Materials</div></a>
            <a href="student-routine.php" class="nav-icon"><i class="bi bi-calendar-week fs-4"></i><div>Routine</div></a>
            <a href="student-results.php" class="nav-icon"><i class="bi bi-trophy fs-4"></i><div>Results</div></a>
        <?php elseif ($role === 'Parents'): ?>
            <a href="parent-child-report.php" class="nav-icon"><i class="bi bi-file-person fs-4"></i><div>Report</div></a>
            <a href="parent-routine.php" class="nav-icon"><i class="bi bi-calendar3 fs-4"></i><div>Routine</div></a>
            <a href="attendance.php" class="nav-icon"><i class="bi bi-check2-square fs-4"></i><div>Attendance</div></a>
        <?php endif; ?>

        <!-- Logout always -->
        <a href="./logout.php" class="nav-icon text-danger"><i class="bi bi-box-arrow-right fs-4"></i><div>Logout</div></a>
    </div>
</div>

