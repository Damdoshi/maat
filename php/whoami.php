<?php
header('Content-Type: application/json');
echo json_encode($_AUTH ?? NULL, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
