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

// Function to get WHOIS data from free API
function getWhoisData($domain) {
    $url = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_whoisxml&domainName=" . urlencode($domain) . "&outputFormat=json";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        return ['error' => 'WHOIS API request failed'];
    }
    
    $data = json_decode($response, true);
    if (isset($data['WhoisRecord']['rawText'])) {
        return ['results' => explode("\n", $data['WhoisRecord']['rawText'])];
    }
    
    return ['error' => 'Invalid WHOIS response'];
}

// Function to get geolocation data
function getGeolocationData($ip) {
    $url = "http://ip-api.com/json/" . urlencode($ip);
    $response = file_get_contents($url);
    return json_decode($response, true);
}

// Function to check DNSBL
function checkDNSBL($ip) {
    $dnsbls = [
        'Spamhaus ZEN' => 'zen.spamhaus.org',
        'SORBS' => 'dnsbl.sorbs.net',
        'SpamCop' => 'bl.spamcop.net',
        'UCEProtect' => 'dnsbl-1.uceprotect.net'
    ];
    
    $results = [];
    $reversedIp = implode('.', array_reverse(explode('.', $ip)));
    
    foreach ($dnsbls as $name => $zone) {
        $query = $reversedIp . '.' . $zone;
        $result = dns_get_record($query, DNS_A);
        $results[$name] = [
            'listed' => !empty($result),
            'zone' => $zone,
            'details' => !empty($result) ? $result[0]['ip'] : null
        ];
    }
    
    return $results;
}

// Function to perform DNS lookup with multiple resolvers
function performDNSLookup($host, $type, $resolver) {
    $resolvers = [
        'google' => '8.8.8.8',
        'cloudflare' => '1.1.1.1',
        'opendns' => '208.67.222.222',
        'quad9' => '9.9.9.9'
    ];
    
    if (!isset($resolvers[$resolver])) {
        return ['error' => 'Invalid resolver'];
    }
    
    $command = "dig @" . $resolvers[$resolver] . " " . escapeshellarg($host) . " " . escapeshellarg($type) . " +short";
    $output = [];
    exec($command, $output, $returnVar);
    
    if ($returnVar !== 0) {
        return ['error' => 'DNS lookup failed'];
    }
    
    return $output;
}

// Function to perform reverse DNS lookup
function performReverseLookup($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return ['error' => 'Invalid IP address'];
    }
    
    $command = "dig -x " . escapeshellarg($ip) . " +short";
    $output = [];
    exec($command, $output, $returnVar);
    
    if ($returnVar !== 0) {
        return ['error' => 'Reverse lookup failed'];
    }
    
    return $output;
}

// Backend functionality
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    $action = $_POST['action'] ?? '';
    $input = sanitizeInput($_POST['input'] ?? '');
    
    if (empty($input)) {
        echo json_encode(['error' => 'Invalid input']);
        exit;
    }
    
    $response = [];
    
    switch ($action) {
        case 'dns':
            $type = sanitizeInput($_POST['type'] ?? 'A');
            $resolver = sanitizeInput($_POST['resolver'] ?? 'google');
            $result = performDNSLookup($input, $type, $resolver);
            if (isset($result['error'])) {
                $response = ['error' => $result['error']];
            } else {
                $response = [
                    'results' => $result,
                    'completed' => true
                ];
            }
            break;
            
        case 'reverse':
            $result = performReverseLookup($input);
            if (isset($result['error'])) {
                $response = ['error' => $result['error']];
            } else {
                $response = [
                    'results' => $result,
                    'completed' => true
                ];
            }
            break;
            
        case 'geolocation':
            $geoData = getGeolocationData($input);
            if ($geoData && $geoData['status'] === 'success') {
                $response = [
                    'results' => $geoData,
                    'completed' => true
                ];
            } else {
                $response = ['error' => 'Geolocation lookup failed'];
            }
            break;
            
        case 'dnsbl':
            $dnsblResults = checkDNSBL($input);
            $response = [
                'results' => $dnsblResults,
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
    <title>DNS Tools - AI DNS Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/style.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="dark-theme">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-search me-2"></i>
                DNS Tools
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="troubleshooting.php">
                            <i class="fas fa-network-wired me-2"></i>Network Diagnostics
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
                            <i class="fas fa-globe me-2"></i>
                            DNS Lookup
                        </h3>
                    </div>
                    <div class="card-body">
                        <form id="dnsForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">Host</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-globe"></i></span>
                                    <input type="text" class="form-control" id="dnsHost" name="input" 
                                           pattern="^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$"
                                           title="Enter a valid hostname"
                                           placeholder="example.com" required>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Record Type</label>
                                    <select class="form-select" id="dnsType" name="type">
                                        <option value="A">A</option>
                                        <option value="AAAA">AAAA</option>
                                        <option value="MX">MX</option>
                                        <option value="NS">NS</option>
                                        <option value="TXT">TXT</option>
                                        <option value="CNAME">CNAME</option>
                                    </select>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Resolver</label>
                                    <select class="form-select" id="dnsResolver" name="resolver">
                                        <option value="google">Google (8.8.8.8)</option>
                                        <option value="cloudflare">Cloudflare (1.1.1.1)</option>
                                        <option value="opendns">OpenDNS (208.67.222.222)</option>
                                        <option value="quad9">Quad9 (9.9.9.9)</option>
                                    </select>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-search me-2"></i>Lookup
                            </button>
                        </form>
                        <div id="dnsResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="dnsStatus"></div>
                            <pre class="bg-dark text-light p-3 rounded" id="dnsOutput"></pre>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 mb-4">
                <div class="card dark-card h-100">
                    <div class="card-header">
                        <h3 class="mb-0">
                            <i class="fas fa-map-marker-alt me-2"></i>
                            Geolocation
                        </h3>
                    </div>
                    <div class="card-body">
                        <form id="geoForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">IP Address</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-network-wired"></i></span>
                                    <input type="text" class="form-control" id="geoIp" name="input" 
                                           pattern="^(\d{1,3}\.){3}\d{1,3}$"
                                           title="Enter a valid IP address"
                                           placeholder="8.8.8.8" required>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-search me-2"></i>Lookup
                            </button>
                        </form>
                        <div id="geoResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="geoStatus"></div>
                            <div id="geoOutput" class="bg-dark text-light p-3 rounded"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 mb-4">
                <div class="card dark-card h-100">
                    <div class="card-header">
                        <h3 class="mb-0">
                            <i class="fas fa-exchange-alt me-2"></i>
                            Reverse DNS
                        </h3>
                    </div>
                    <div class="card-body">
                        <form id="reverseForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">IP Address</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-network-wired"></i></span>
                                    <input type="text" class="form-control" id="reverseIp" name="input" 
                                           pattern="^(\d{1,3}\.){3}\d{1,3}$"
                                           title="Enter a valid IP address"
                                           placeholder="8.8.8.8" required>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-search me-2"></i>Lookup
                            </button>
                        </form>
                        <div id="reverseResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="reverseStatus"></div>
                            <pre class="bg-dark text-light p-3 rounded" id="reverseOutput"></pre>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 mb-4">
                <div class="card dark-card h-100">
                    <div class="card-header">
                        <h3 class="mb-0">
                            <i class="fas fa-shield-alt me-2"></i>
                            DNSBL Check
                        </h3>
                    </div>
                    <div class="card-body">
                        <form id="dnsblForm" class="mb-3">
                            <div class="mb-3">
                                <label class="form-label">IP Address</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-network-wired"></i></span>
                                    <input type="text" class="form-control" id="dnsblIp" name="input" 
                                           pattern="^(\d{1,3}\.){3}\d{1,3}$"
                                           title="Enter a valid IP address"
                                           placeholder="8.8.8.8" required>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-search me-2"></i>Check
                            </button>
                        </form>
                        <div id="dnsblResults" class="mt-3" style="display: none;">
                            <div class="alert alert-info" id="dnsblStatus"></div>
                            <div id="dnsblOutput" class="bg-dark text-light p-3 rounded"></div>
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

        // DNS form handler
        const dnsForm = document.getElementById('dnsForm');
        const dnsResults = document.getElementById('dnsResults');
        const dnsStatus = document.getElementById('dnsStatus');
        const dnsOutput = document.getElementById('dnsOutput');

        dnsForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const host = document.getElementById('dnsHost').value;
            const type = document.getElementById('dnsType').value;
            const resolver = document.getElementById('dnsResolver').value;
            
            dnsStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Performing DNS lookup...';
            dnsResults.style.display = 'block';
            dnsOutput.textContent = '';
            
            startCheck('dns', host, dnsStatus, dnsOutput, { type: type, resolver: resolver });
        });

        // Geolocation form handler
        const geoForm = document.getElementById('geoForm');
        const geoResults = document.getElementById('geoResults');
        const geoStatus = document.getElementById('geoStatus');
        const geoOutput = document.getElementById('geoOutput');

        geoForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const ip = document.getElementById('geoIp').value;
            
            geoStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Looking up geolocation...';
            geoResults.style.display = 'block';
            geoOutput.innerHTML = '';
            
            startCheck('geolocation', ip, geoStatus, geoOutput);
        });

        // Reverse DNS form handler
        const reverseForm = document.getElementById('reverseForm');
        const reverseResults = document.getElementById('reverseResults');
        const reverseStatus = document.getElementById('reverseStatus');
        const reverseOutput = document.getElementById('reverseOutput');

        reverseForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const ip = document.getElementById('reverseIp').value;
            
            reverseStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Performing reverse lookup...';
            reverseResults.style.display = 'block';
            reverseOutput.textContent = '';
            
            startCheck('reverse', ip, reverseStatus, reverseOutput);
        });

        // DNSBL form handler
        const dnsblForm = document.getElementById('dnsblForm');
        const dnsblResults = document.getElementById('dnsblResults');
        const dnsblStatus = document.getElementById('dnsblStatus');
        const dnsblOutput = document.getElementById('dnsblOutput');

        dnsblForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const ip = document.getElementById('dnsblIp').value;
            
            dnsblStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Checking DNSBLs...';
            dnsblResults.style.display = 'block';
            dnsblOutput.innerHTML = '';
            
            startCheck('dnsbl', ip, dnsblStatus, dnsblOutput);
        });

        // Function to start a check
        function startCheck(type, target, statusElement, outputElement, additionalParams = {}) {
            const formData = new FormData();
            formData.append('action', type);
            formData.append('input', target);
            
            for (const [key, value] of Object.entries(additionalParams)) {
                formData.append(key, value);
            }

            fetch('dns-tools.php', {
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

                if (type === 'geolocation') {
                    const geo = data.results;
                    outputElement.innerHTML = `
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Country:</strong> ${geo.country} (${geo.countryCode})</p>
                                <p><strong>Region:</strong> ${geo.regionName}</p>
                                <p><strong>City:</strong> ${geo.city}</p>
                                <p><strong>ISP:</strong> ${geo.isp}</p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Latitude:</strong> ${geo.lat}</p>
                                <p><strong>Longitude:</strong> ${geo.lon}</p>
                                <p><strong>Timezone:</strong> ${geo.timezone}</p>
                                <p><strong>Organization:</strong> ${geo.org}</p>
                            </div>
                        </div>
                    `;
                } else if (type === 'dnsbl') {
                    const dnsbls = data.results;
                    let html = '<div class="table-responsive"><table class="table table-dark table-striped">';
                    html += '<thead><tr><th>DNSBL</th><th>Status</th><th>Details</th></tr></thead><tbody>';
                    
                    for (const [name, info] of Object.entries(dnsbls)) {
                        const status = info.listed ? 
                            '<span class="badge bg-danger">Listed</span>' : 
                            '<span class="badge bg-success">Clean</span>';
                        
                        html += `<tr>
                            <td>${name}</td>
                            <td>${status}</td>
                            <td>${info.details || '-'}</td>
                        </tr>`;
                    }
                    
                    html += '</tbody></table></div>';
                    outputElement.innerHTML = html;
                } else {
                    outputElement.textContent = data.results.join('\n');
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