document.addEventListener('DOMContentLoaded', function() {
    // Ping form handler
    const pingForm = document.getElementById('pingForm');
    const pingResults = document.getElementById('pingResults');
    const pingStatus = document.getElementById('pingStatus');
    const pingTable = document.getElementById('pingTable').getElementsByTagName('tbody')[0];

    pingForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const host = document.getElementById('pingHost').value;
        
        pingStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Initiating ping check...';
        pingResults.style.display = 'block';
        pingTable.innerHTML = '';
        
        startCheck('ping', host, pingStatus, pingTable, formatPingResults);
    });

    // Traceroute form handler
    const tracerouteForm = document.getElementById('tracerouteForm');
    const tracerouteResults = document.getElementById('tracerouteResults');
    const tracerouteStatus = document.getElementById('tracerouteStatus');
    const tracerouteTable = document.getElementById('tracerouteTable').getElementsByTagName('tbody')[0];

    tracerouteForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const host = document.getElementById('tracerouteHost').value;
        
        tracerouteStatus.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Initiating traceroute...';
        tracerouteResults.style.display = 'block';
        tracerouteTable.innerHTML = '';
        
        startCheck('traceroute', host, tracerouteStatus, tracerouteTable, formatTracerouteResults);
    });

    // Port check form handler
    const portCheckForm = document.getElementById('portCheckForm');
    const portCheckResults = document.getElementById('portCheckResults');
    const portCheckStatus = document.getElementById('portCheckStatus');
    const portCheckTable = document.getElementById('portCheckTable').getElementsByTagName('tbody')[0];

    portCheckForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const host = document.getElementById('portCheckHost').value;
        const port = document.getElementById('portCheckPort').value;
        const protocol = document.getElementById('portCheckProtocol').value;
        
        portCheckStatus.innerHTML = `<i class="fas fa-spinner fa-spin me-2"></i>Checking ${protocol.toUpperCase()} port ${port}...`;
        portCheckResults.style.display = 'block';
        portCheckTable.innerHTML = '';
        
        startCheck(protocol, `${host}:${port}`, portCheckStatus, portCheckTable, formatPortCheckResults);
    });

    // Function to start a check and poll for results
    function startCheck(type, target, statusElement, tableElement, formatFunction) {
        const formData = new FormData();
        formData.append('action', type);
        formData.append('host', target);

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

            statusElement.innerHTML = `<i class="fas fa-spinner fa-spin me-2"></i>${data.message}`;
            pollResults(data.request_id, statusElement, tableElement, formatFunction);
        })
        .catch(error => {
            statusElement.innerHTML = `<i class="fas fa-exclamation-circle me-2"></i>Error: ${error.message}`;
        });
    }

    // Function to poll for results
    function pollResults(requestId, statusElement, tableElement, formatFunction) {
        const formData = new FormData();
        formData.append('action', 'get_results');
        formData.append('request_id', requestId);

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

            if (!data.completed) {
                setTimeout(() => pollResults(requestId, statusElement, tableElement, formatFunction), 2000);
                return;
            }

            statusElement.innerHTML = '<i class="fas fa-check-circle me-2"></i>Check completed';
            formatFunction(data.results, tableElement);
        })
        .catch(error => {
            statusElement.innerHTML = `<i class="fas fa-exclamation-circle me-2"></i>Error: ${error.message}`;
        });
    }

    // Format functions for different types of results
    function formatPingResults(results, tableElement) {
        tableElement.innerHTML = '';
        Object.entries(results).forEach(([node, data]) => {
            if (data[0] && data[0].result) {
                const ping = data[0].result[0];
                const row = tableElement.insertRow();
                row.innerHTML = `
                    <td>${node}</td>
                    <td>${ping.min || 'N/A'}</td>
                    <td>${ping.avg || 'N/A'}</td>
                    <td>${ping.max || 'N/A'}</td>
                    <td><span class="badge bg-${ping.avg ? 'success' : 'danger'}">${ping.avg ? 'Online' : 'Offline'}</span></td>
                `;
            }
        });
    }

    function formatTracerouteResults(results, tableElement) {
        tableElement.innerHTML = '';
        Object.entries(results).forEach(([node, data]) => {
            if (data[0] && data[0].result) {
                data[0].result.forEach((hop, index) => {
                    const row = tableElement.insertRow();
                    row.innerHTML = `
                        <td>${index + 1}</td>
                        <td>${hop.ip || 'N/A'}</td>
                        <td>${hop.hostname || 'N/A'}</td>
                        <td>${hop.time || 'N/A'}</td>
                    `;
                });
            }
        });
    }

    function formatPortCheckResults(results, tableElement) {
        tableElement.innerHTML = '';
        Object.entries(results).forEach(([node, data]) => {
            if (data[0] && data[0].result) {
                const check = data[0].result[0];
                const row = tableElement.insertRow();
                row.innerHTML = `
                    <td>${node}</td>
                    <td><span class="badge bg-${check.status === 'OK' ? 'success' : 'danger'}">${check.status || 'Unknown'}</span></td>
                    <td>${check.time || 'N/A'}</td>
                `;
            }
        });
    }
}); 