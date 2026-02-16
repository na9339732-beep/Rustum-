<?php
session_start();
include '../config/db.php';

// Security check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Admin') {
    die("Unauthorized access");
}

// Tell browser it's a CSV file
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename=attendance_export.csv');

// Output to browser
$output = fopen('php://output', 'w');

// CSV Header
fputcsv($output, ['Date', 'Class', 'Present', 'Absent', 'Leave']);

// SQL
$sql = "
    SELECT 
        a.attendance_date,
        c.class_name,
        SUM(a.status = 'Present') AS present_count,
        SUM(a.status = 'Absent') AS absent_count,
        SUM(a.status = 'Leave') AS leave_count
    FROM attendance a
    JOIN classes c ON c.class_id = a.class_id
    GROUP BY a.attendance_date, c.class_name
    ORDER BY a.attendance_date DESC
";

$result = mysqli_query($conn, $sql);

// Export rows
while ($row = mysqli_fetch_assoc($result)) {
    fputcsv($output, [
        $row['attendance_date'],
        $row['class_name'],
        $row['present_count'],
        $row['absent_count'],
        $row['leave_count']
    ]);
}

fclose($output);
exit;
?>
