<?php
use Dompdf\Dompdf;
use Dompdf\Options;

require '../vendor/autoload.php';

include '../config/db.php';

$student_id = intval($_GET['student_id']);

// Fetch data
$result = $conn->query("SELECT * FROM results WHERE student_id = $student_id");

// Convert logo to base64
$logoPath = "../assets/images/logo.png";
$logoData = base64_encode(file_get_contents($logoPath));
$logo = 'data:image/png;base64,' . $logoData;

// HTML
$html = "
<!DOCTYPE html>
<html>
<head>
<style>
    body { font-family: DejaVu Sans, sans-serif; }
    .header { text-align: center; }
    img { width: 120px; margin-bottom: 10px; }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th, td {
        border: 1px solid #000;
        padding: 8px;
        text-align: center;
    }
    th { background: #f2f2f2; }
</style>
</head>
<body>

<div class='header'>
    <img src='$logo'>
    <h2>Student Academic Report</h2>
</div>

<table>
<tr>
    <th>ID</th>
    <th>Subject</th>
    <th>Marks</th>
    <th>Grade</th>
    <th>Exam Term</th>
    <th>Session</th>
    <th>Date</th>
</tr>
";

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $html .= "
        <tr>
            <td>{$row['id']}</td>
            <td>{$row['subject']}</td>
            <td>{$row['marks']}</td>
            <td>{$row['grade']}</td>
            <td>{$row['exam_term']}</td>
            <td>{$row['session_id']}</td>
            <td>{$row['created_at']}</td>
        </tr>
        ";
    }
} else {
    $html .= "<tr><td colspan='7'>No Records</td></tr>";
}

$html .= "
</table>
</body>
</html>
";

// Dompdf
$options = new Options();
$options->set('isRemoteEnabled', true);

$dompdf = new Dompdf($options);
$dompdf->loadHtml($html);
$dompdf->setPaper('A4', 'portrait');
$dompdf->render();

// Download
$dompdf->stream("student_report_$student_id.pdf", ["Attachment" => true]);

$conn->close();

