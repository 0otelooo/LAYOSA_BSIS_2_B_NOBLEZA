<?php
$upload_dir = 'uploads/';

if (is_writable($upload_dir)) {
    echo 'The uploads folder is writable.';
} else {
    echo 'The uploads folder is not writable.';
}
?>