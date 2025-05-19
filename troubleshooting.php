<?php
// Security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com;");

// Function to sanitize input
function sanitizeInput($input) {
    return preg_replace('/[^a-zA-Z0-9\.\-\:]/', '', $input);
}

// Function to validate hostname
function isValidHostname($hostname) {
    return preg_match('/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i', $hostname) &&
           preg_match('/^.{1,253}$/', $hostname) &&
           preg_match('/^[^\.]{1,63}(\.[^\.]{1,63})*$/', $hostname);
}

// Function to validate port number
function isValidPort($port) {
    return is_numeric($port) && $port >= 1 && $port <= 65535;
}

// Function to safely execute command
function safeExecute($command) {
    $escapedCommand = escapeshellcmd($command);
    $output = [];
    $returnVar = 0;
    
    exec($escapedCommand, $output, $returnVar);
    
    if ($returnVar !== 0) {
        return ['error' => 'Command execution failed'];
    }
    
    return $output;
}

// Function to parse ping results for packet loss
function parsePingResults($results) {
    $packets = [
        'transmitted' => 0,
        'received' => 0,
        'lost' => 0,
        'loss_percent' => 0,
        'times' => []
    ];
    
    foreach ($results as $line) {
        if (preg_match('/(\d+) packets transmitted, (\d+) received, (\d+)% packet loss/', $line, $matches)) {
            $packets['transmitted'] = (int)$matches[1];
            $packets['received'] = (int)$matches[2];
            $packets['lost'] = $packets['transmitted'] - $packets['received'];
            $packets['loss_percent'] = (float)$matches[3];
        } elseif (preg_match('/time=([\d.]+) ms/', $line, $matches)) {
            $packets['times'][] = (float)$matches[1];
        }
    }
    
    return $packets;
}

// Function to check port
function checkPort($host, $port, $protocol, $timeout) {
    $startTime = microtime(true);
    $command = '';
    if ($protocol === 'tcp') {
        $command = "timeout {$timeout} bash -c 'cat < /dev/null > /dev/tcp/" . escapeshellarg($host) . "/" . escapeshellarg($port) . "' 2>&1";
    } else {
        $command = "timeout {$timeout} bash -c 'cat < /dev/null > /dev/udp/" . escapeshellarg($host) . "/" . escapeshellarg($port) . "' 2>&1";
    }
    
    $output = [];
    $returnVar = 0;
    exec($command, $output, $returnVar);
    
    $endTime = microtime(true);
    $responseTime = round(($endTime - $startTime) * 1000, 2); // Convert to milliseconds
    
    $status = 'closed';
    if ($returnVar === 0) {
        $status = 'open';
    } elseif (strpos(implode(' ', $output), 'timeout') !== false) {
        $status = 'filtered';
    }
    
    $result = [
        'success' => $returnVar === 0,
        'output' => $output,
        'protocol' => $protocol,
        'port' => $port,
        'host' => $host,
        'status' => $status,
        'response_time' => $responseTime
    ];
    
    return $result;
}

// Backend functionality
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    $action = $_POST['action'] ?? '';
    $host = sanitizeInput($_POST['host'] ?? '');
    
    if (empty($host) || !isValidHostname($host)) {
        echo json_encode(['error' => 'Invalid hostname']);
        exit;
    }
    
    $response = [];
    
    switch ($action) {
        case 'ping':
            $count = isset($_POST['count']) ? (int)$_POST['count'] : 10;
            $count = max(1, min(20, $count)); // Limit between 1 and 20
            $command = "ping -c {$count} " . escapeshellarg($host);
            $result = safeExecute($command);
            if (isset($result['error'])) {
                $response = ['error' => $result['error']];
            } else {
                $packets = parsePingResults($result);
                $response = [
                    'results' => $result,
                    'packets' => $packets,
                    'completed' => true
                ];
            }
            break;
            
        case 'traceroute':
            $maxHops = isset($_POST['max_hops']) ? (int)$_POST['max_hops'] : 30;
            $maxHops = max(1, min(64, $maxHops)); // Limit between 1 and 64
            $command = "traceroute -n -m {$maxHops} " . escapeshellarg($host);
            $result = safeExecute($command);
            if (isset($result['error'])) {
                $response = ['error' => $result['error']];
            } else {
                $response = [
                    'results' => $result,
                    'completed' => true
                ];
            }
            break;
            
        case 'tcp':
        case 'udp':
            $port = sanitizeInput($_POST['port'] ?? '');
            if (!isValidPort($port)) {
                echo json_encode(['error' => 'Invalid port number']);
                exit;
            }
            
            $timeout = isset($_POST['timeout']) ? (int)$_POST['timeout'] : 5;
            $timeout = max(1, min(30, $timeout)); // Limit between 1 and 30 seconds
            
            $result = checkPort($host, $port, $action, $timeout);
            $response = [
                'results' => [
                    sprintf(
                        "Port %s (%s) is %s on %s",
                        $port,
                        strtoupper($action),
                        $result['success'] ? 'open' : 'closed',
                        $host
                    ),
                    ...$result['output']
                ],
                'completed' => true
            ];
            break;
            
        default:
            $response = ['error' => 'Invalid action'];
    }
    
    echo json_encode($response);
    exit;
}

// Frontend HTML
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Diagnostics - AI DNS Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/style.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="dark-theme">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-network-wired me-2"></i>
                Network Diagnostics
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="dns-tools.php">
                            <i class="fas fa-search me-2"></i>DNS Tools
                        </a>
                    </li>
                </ul>
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <button class="btn btn-outline-light" id="themeToggle">
                            <i class="fas fa-moon me-2"></i>
                            <span>Toggle Theme</span>
                        </button>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card dark-card h-100">
                    <div class="card-header">
                        <h3 class="mb-0">
                            <i class="fas fa-broadcast-tower me-2"></i>
                            Packet Loss Monitor
                        </h3>
                    </div>
                    <div class="card-body">
                            <form id="pingForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">Host</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-globe"></i></span>
                                    <input type="text" class="form-control" id="pingHost" name="host" 
                                           pattern="^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$"
                                           title="Enter a valid hostname"
                                           placeholder="example.com" required>
                                </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Ping Count (10-20)</label>
                                <input type="number" class="form-control" id="pingCount" name="count" 
                                       min="10" max="20" value="10">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-play me-2"></i>Start Monitoring
                            </button>
                            </form>
                            <div id="pingResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="pingStatus"></div>
                            <div class="row">
                                <div class="col-md-6">
                                    <canvas id="packetLossChart"></canvas>
                                </div>
                                <div class="col-md-6">
                                    <div class="card bg-dark text-light">
                                        <div class="card-body">
                                            <h5 class="card-title">Statistics</h5>
                                            <p class="mb-1">Transmitted: <span id="transmitted">0</span></p>
                                            <p class="mb-1">Received: <span id="received">0</span></p>
                                            <p class="mb-1">Lost: <span id="lost">0</span></p>
                                            <p class="mb-0">Loss: <span id="lossPercent">0</span>%</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <pre class="bg-dark text-light p-3 rounded mt-3" id="pingOutput"></pre>
                        </div>
                    </div>
                            </div>
                        </div>

            <div class="col-md-6 mb-4">
                <div class="card dark-card h-100">
                    <div class="card-header">
                        <h3 class="mb-0">
                                <i class="fas fa-route me-2"></i>
                                Traceroute
                            </h3>
                    </div>
                    <div class="card-body">
                            <form id="tracerouteForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">Host</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-globe"></i></span>
                                    <input type="text" class="form-control" id="tracerouteHost" name="host"
                                           pattern="^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$"
                                           title="Enter a valid hostname"
                                           placeholder="example.com" required>
                                </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Max Hops</label>
                                <input type="number" class="form-control" id="tracerouteMaxHops" name="max_hops" 
                                       min="1" max="64" value="30">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-play me-2"></i>Start Traceroute
                            </button>
                            </form>
                            <div id="tracerouteResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="tracerouteStatus"></div>
                                <pre class="bg-dark text-light p-3 rounded" id="tracerouteOutput"></pre>
                        </div>
                    </div>
                            </div>
                        </div>

            <div class="col-md-6 mb-4">
                <div class="card dark-card h-100">
                    <div class="card-header">
                        <h3 class="mb-0">
                            <i class="fas fa-plug me-2"></i>
                            Port Checker
                        </h3>
                    </div>
                    <div class="card-body">
                        <form id="portCheckForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">Host</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-globe"></i></span>
                                    <input type="text" class="form-control" id="portCheckHost" name="host"
                                           pattern="^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$"
                                           title="Enter a valid hostname"
                                           placeholder="example.com" required>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Port</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-ethernet"></i></span>
                                        <input type="number" class="form-control" id="portCheckPort" name="port"
                                               min="1" max="65535" placeholder="Port" required>
                                    </div>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Protocol</label>
                                    <select class="form-select" id="portCheckProtocol" name="protocol">
                                        <option value="tcp">TCP</option>
                                        <option value="udp">UDP</option>
                                    </select>
                                </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Timeout (seconds)</label>
                                <input type="number" class="form-control" id="portCheckTimeout" name="timeout" 
                                       min="1" max="30" value="5">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-play me-2"></i>Check Port
                            </button>
                        </form>
                        <div id="portCheckResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="portCheckStatus"></div>
                            
                            <!-- Status Badge -->
                            <div class="text-center mb-3">
                                <div id="portStatusBadge" class="badge fs-5 p-2"></div>
                            </div>
                            
                            <!-- Response Time -->
                            <div class="text-center mb-3">
                                <div class="d-inline-block bg-dark text-light p-2 rounded">
                                    <i class="fas fa-clock me-2"></i>
                                    Response Time: <span id="responseTime">0</span> ms
                                </div>
                            </div>
                            
                            <!-- Sparkline Chart -->
                            <div class="mb-3">
                                <canvas id="responseTimeSparkline" height="50"></canvas>
                            </div>
                            
                            <!-- Main Chart -->
                            <div class="mb-3">
                                <canvas id="portStatusChart"></canvas>
                            </div>
                            
                            <pre class="bg-dark text-light p-3 rounded" id="portCheckOutput"></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Theme toggle
        const themeToggle = document.getElementById('themeToggle');
        const body = document.body;
        const icon = themeToggle.querySelector('i');
        const text = themeToggle.querySelector('span');
        
        themeToggle.addEventListener('click', function() {
            body.classList.toggle('dark-theme');
            if (body.classList.contains('dark-theme')) {
                icon.className = 'fas fa-sun me-2';
                text.textContent = 'Light Theme';
            } else {
                icon.className = 'fas fa-moon me-2';
                text.textContent = 'Dark Theme';
            }
        });

        // Initialize packet loss chart
        const ctx = document.getElementById('packetLossChart').getContext('2d');
        let packetLossChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Received', 'Lost'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#28a745', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#fff'
                        }
                    }
                }
            }
        });

        // Initialize response time history
        let responseTimeHistory = [];
        let sparklineChart = null;
        let portStatusChart = null;

        // Function to update status badge
        function updateStatusBadge(status, responseTime) {
            const badge = document.getElementById('portStatusBadge');
            let color, icon, text;
            
            switch(status) {
                case 'open':
                    color = 'bg-success';
                    icon = 'fa-check-circle';
                    text = 'Port Open';
                    break;
                case 'closed':
                    color = 'bg-danger';
                    icon = 'fa-times-circle';
                    text = 'Port Closed';
                    break;
                case 'filtered':
                    color = 'bg-warning';
                    icon = 'fa-clock';
                    text = 'Port Filtered';
                    break;
                default:
                    color = 'bg-secondary';
                    icon = 'fa-question-circle';
                    text = 'Unknown';
            }
            
            badge.className = `badge ${color} fs-5 p-2`;
            badge.innerHTML = `<i class="fas ${icon} me-2"></i>${text}`;
        }

        // Function to update sparkline
        function updateSparkline(responseTime) {
            responseTimeHistory.push(responseTime);
            if (responseTimeHistory.length > 5) {
                responseTimeHistory.shift();
            }
            
            if (sparklineChart) {
                sparklineChart.destroy();
            }
            
            const ctx = document.getElementById('responseTimeSparkline').getContext('2d');
            sparklineChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: Array(responseTimeHistory.length).fill(''),
                    datasets: [{
                        data: responseTimeHistory,
                        borderColor: '#28a745',
                        borderWidth: 2,
                        fill: false,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            display: false
                        },
                        y: {
                            display: false
                        }
                    },
                    elements: {
                        point: {
                            radius: 0
                        }
                    }
                }
            });
        }

        // Function to update port status chart
        function updatePortStatusChart(status, responseTime) {
            if (portStatusChart) {
                portStatusChart.destroy();
            }
            
            const ctx = document.getElementById('portStatusChart').getContext('2d');
            portStatusChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Response Time'],
                    datasets: [{
                        label: 'Response Time (ms)',
                        data: [responseTime],
                        backgroundColor: status === 'open' ? '#28a745' : 
                                       status === 'filtered' ? '#ffc107' : '#dc3545'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Milliseconds'
                            }
                        }
                    }
                }
            });
        }

        // Ping form handler
        const pingForm = document.getElementById('pingForm');
        const pingResults = document.getElementById('pingResults');
        const pingStatus = document.getElementById('pingStatus');
        const pingOutput = document.getElementById('pingOutput');

        pingForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const host = document.getElementById('pingHost').value;
            const count = document.getElementById('pingCount').value;
            
            pingStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Running ping check...';
            pingResults.style.display = 'block';
            pingOutput.textContent = '';
            
            startCheck('ping', host, pingStatus, pingOutput, { count: count });
        });

        // Traceroute form handler
        const tracerouteForm = document.getElementById('tracerouteForm');
        const tracerouteResults = document.getElementById('tracerouteResults');
        const tracerouteStatus = document.getElementById('tracerouteStatus');
        const tracerouteOutput = document.getElementById('tracerouteOutput');

        tracerouteForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const host = document.getElementById('tracerouteHost').value;
            const maxHops = document.getElementById('tracerouteMaxHops').value;
            
            tracerouteStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Running traceroute...';
            tracerouteResults.style.display = 'block';
            tracerouteOutput.textContent = '';
            
            startCheck('traceroute', host, tracerouteStatus, tracerouteOutput, { max_hops: maxHops });
        });

        // Port check form handler
        const portCheckForm = document.getElementById('portCheckForm');
        const portCheckResults = document.getElementById('portCheckResults');
        const portCheckStatus = document.getElementById('portCheckStatus');
        const portCheckOutput = document.getElementById('portCheckOutput');

        portCheckForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const host = document.getElementById('portCheckHost').value;
            const port = document.getElementById('portCheckPort').value;
            const protocol = document.getElementById('portCheckProtocol').value;
            const timeout = document.getElementById('portCheckTimeout').value;
            
            portCheckStatus.innerHTML = `<i class="fas fa-spinner fa-spin me-2"></i>Checking ${protocol.toUpperCase()} port ${port}...`;
            portCheckResults.style.display = 'block';
            portCheckOutput.textContent = '';
            
            startCheck(protocol, host, portCheckStatus, portCheckOutput, { 
                port: port,
                timeout: timeout 
            });
        });

        // Function to start a check
        function startCheck(type, target, statusElement, outputElement, additionalParams = {}) {
            const formData = new FormData();
            formData.append('action', type);
            
            if (type === 'tcp' || type === 'udp') {
                formData.append('host', target);
                formData.append('port', additionalParams.port);
                formData.append('timeout', additionalParams.timeout);
            } else {
                formData.append('host', target);
            }
            
            for (const [key, value] of Object.entries(additionalParams)) {
                if (key !== 'port' && key !== 'timeout') {
                    formData.append(key, value);
                }
            }

            fetch('troubleshooting.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    statusElement.innerHTML = `<i class="fas fa-exclamation-circle me-2"></i>Error: ${data.error}`;
                    return;
                }

                statusElement.innerHTML = '<i class="fas fa-check-circle me-2"></i>Check completed';
                outputElement.textContent = data.results.join('\n');

                if (type === 'ping' && data.packets) {
                    const packets = data.packets;
                    document.getElementById('transmitted').textContent = packets.transmitted;
                    document.getElementById('received').textContent = packets.received;
                    document.getElementById('lost').textContent = packets.lost;
                    document.getElementById('lossPercent').textContent = packets.loss_percent;

                    packetLossChart.data.datasets[0].data = [packets.received, packets.lost];
                    packetLossChart.update();
                } else if (type === 'tcp' || type === 'udp') {
                    const result = data.results[0];
                    const status = result.includes('open') ? 'open' : 
                                 result.includes('filtered') ? 'filtered' : 'closed';
                    const responseTime = data.response_time || 0;
                    
                    document.getElementById('responseTime').textContent = responseTime;
                    updateStatusBadge(status, responseTime);
                    updateSparkline(responseTime);
                    updatePortStatusChart(status, responseTime);
                }
            })
            .catch(error => {
                statusElement.innerHTML = `<i class="fas fa-exclamation-circle me-2"></i>Error: ${error.message}`;
            });
        }
    });
    </script>
</body>
</html> 