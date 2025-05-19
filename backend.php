<?php
header('Content-Type: application/json');

// Load environment variables
$env = parse_ini_file('.env');

// Function to get geolocation
function get_geolocation($ip) {
    $response = @file_get_contents("http://ip-api.com/json/$ip");
    if ($response === false) {
        return 'Unknown';
    }
    
    $geo = json_decode($response, true);
    return ($geo && $geo['status'] === 'success') ? "{$geo['city']}, {$geo['country']}" : 'Unknown';
}

// Function to execute command safely
function executeCommand($command, $args = []) {
    // Validate and sanitize arguments
    $sanitizedArgs = array_map(function($arg) {
        // Remove any potentially dangerous characters
        return preg_replace('/[^a-zA-Z0-9\.\-_]/', '', $arg);
    }, $args);

    // Build the command with proper escaping
    $cmd = escapeshellcmd($command);
    foreach ($sanitizedArgs as $arg) {
        $cmd .= ' ' . escapeshellarg($arg);
    }

    // Set a timeout for the command
    $descriptorspec = array(
        1 => array("pipe", "w"), // stdout
        2 => array("pipe", "w")  // stderr
    );

    $process = proc_open($cmd, $descriptorspec, $pipes);
    
    if (is_resource($process)) {
        // Set a timeout of 30 seconds
        $timeout = 30;
        $start = time();
        
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        
        // Close all pipes
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        
        $return_value = proc_close($process);
        
        return [
            'output' => $stdout . ($stderr ? "\nError: " . $stderr : ''),
            'success' => $return_value === 0
        ];
    }
    
    return [
        'output' => 'Failed to execute command',
        'success' => false
    ];
}

// Main processing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle DNS query
    $domain = trim($_POST['domain'] ?? '');
    $recordType = $_POST['recordType'] ?? 'A';
    $resolver = $_POST['resolver'] ?? $env['DEFAULT_RESOLVER'];
    $geolocate = isset($_POST['geolocation']);

    // Handle custom resolver
    if ($resolver === 'custom' && isset($_POST['customResolverInput'])) {
        $resolver = trim($_POST['customResolverInput']);
    }

    if (empty($domain)) {
        echo json_encode(['error' => 'Domain is required']);
        exit;
    }

    // Validate resolver IP
    if (!filter_var($resolver, FILTER_VALIDATE_IP)) {
        echo json_encode(['error' => 'Invalid resolver IP address']);
        exit;
    }

    // Execute dig command
    $result = executeCommand('dig', ['@' . $resolver, $domain, $recordType, '+short']);
    $records = array_filter(explode("\n", trim($result['output'])));

    $output = [];
    foreach ($records as $rec) {
        $recordData = ['record' => $rec];
        if ($geolocate && filter_var($rec, FILTER_VALIDATE_IP)) {
            $recordData['geolocation'] = get_geolocation($rec);
        }
        $output[] = $recordData;
    }

    echo json_encode(['records' => $output]);
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Handle troubleshooting tools
    $tool = $_GET['tool'] ?? '';
    $host = $_GET['host'] ?? '';
    $port = $_GET['port'] ?? '';
    $protocol = $_GET['protocol'] ?? '';

    

    if (empty($host)) {
        echo json_encode(['error' => 'Host is required']);
        exit;
    }

    // Validate host
    if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) && 
        !filter_var($host, FILTER_VALIDATE_IP)) {
        echo json_encode(['error' => 'Invalid host']);
        exit;
    }

    switch ($tool) {
        case 'ping':
            $result = executeCommand('ping', ['-c', '4', $host]);
            echo json_encode($result);
            break;

        case 'traceroute':
            $result = executeCommand('traceroute', [$host]);
            echo json_encode($result);
            break;

        case 'mtr':
            $result = executeCommand('mtr', ['--report', '--report-cycles', '5', $host]);
            echo json_encode($result);
            break;

        case 'portcheck':
            if (empty($port) || !is_numeric($port) || $port < 1 || $port > 65535) {
                echo json_encode(['error' => 'Invalid port number']);
                exit;
            }

            $timeout = 5; // seconds
            $errno = 0;
            $errstr = '';

            if ($protocol === 'tcp') {
                $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
                $success = is_resource($socket);
                if ($success) {
                    fclose($socket);
                }
            } else {
                // UDP check is more complex and may require root privileges
                $socket = @fsockopen("udp://$host", $port, $errno, $errstr, $timeout);
                $success = is_resource($socket);
                if ($success) {
                    fclose($socket);
                }
            }

            echo json_encode([
                'success' => $success,
                'message' => $success ? 
                    "Port $port ($protocol) is open on $host" : 
                    "Port $port ($protocol) is closed or unreachable on $host"
            ]);
            break;

        default:
            echo json_encode(['error' => 'Invalid tool']);
            break;
    }
} else {
    echo json_encode(['error' => 'Invalid request method']);
} 