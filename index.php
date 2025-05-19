<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Tools - Network Diagnostic Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/style.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="dark-theme">
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-network-wired me-2"></i>
                Network Toolkit
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link active" href="index.php">
                            <i class="fas fa-search me-1"></i> 🔍 DNS Tools
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="troubleshooting.php">
                            <i class="fas fa-tools me-1"></i> 🛠️ Troubleshooting
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card dark-card">
                    <div class="card-header">
                        <h1 class="text-center mb-0">
                            <i class="fas fa-search me-2"></i>
                            🔍 DNS Tools
                        </h1>
                    </div>
                    <div class="card-body">
                        <form id="dnsForm" action="backend.php" method="POST">
                            <div class="mb-3">
                                <label for="domain" class="form-label">Domain Name</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-globe"></i></span>
                                    <input type="text" class="form-control" id="domain" name="domain" placeholder="example.com" required>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="recordType" class="form-label">Record Type</label>
                                    <select class="form-select" id="recordType" name="recordType">
                                        <option value="A">A Record</option>
                                        <option value="AAAA">AAAA Record</option>
                                        <option value="MX">MX Record</option>
                                        <option value="TXT">TXT Record</option>
                                        <option value="NS">NS Record</option>
                                        <option value="CNAME">CNAME Record</option>
                                        <option value="SOA">SOA Record</option>
                                    </select>
                                </div>

                                <div class="col-md-6 mb-3">
                                    <label for="resolver" class="form-label">DNS Resolver</label>
                                    <select class="form-select" id="resolver" name="resolver">
                                        <option value="8.8.8.8">Google DNS</option>
                                        <option value="1.1.1.1">Cloudflare</option>
                                        <option value="208.67.222.222">OpenDNS</option>
                                        <option value="custom">Custom</option>
                                    </select>
                                </div>
                            </div>

                            <div id="customResolver" class="mb-3" style="display: none;">
                                <label for="customResolverInput" class="form-label">Custom Resolver IP</label>
                                <input type="text" class="form-control" id="customResolverInput" name="customResolverInput" placeholder="e.g., 8.8.8.8">
                            </div>

                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="geolocation" name="geolocation">
                                <label class="form-check-label" for="geolocation">Show Geolocation</label>
                            </div>

                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="aiSuggestions" name="aiSuggestions" checked>
                                <label class="form-check-label" for="aiSuggestions">Enable AI Suggestions</label>
                            </div>

                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-2"></i>Query DNS
                                </button>
                            </div>
                        </form>

                        <div id="results" class="mt-4" style="display: none;">
                            <h3 class="mb-3">Results</h3>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover">
                                    <thead>
                                        <tr>
                                            <th>Record</th>
                                            <th>Geolocation</th>
                                        </tr>
                                    </thead>
                                    <tbody id="resultsBody">
                                    </tbody>
                                </table>
                            </div>

                            <div id="aiSuggestions" class="mt-3">
                                <h4>AI Analysis</h4>
                                <div id="aiContent" class="alert alert-info">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="js/main.js"></script>
</body>
</html> 