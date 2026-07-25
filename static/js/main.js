document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultsSection = document.getElementById('results');
    const scanOptions = document.querySelectorAll('.btn-option');

    let selectedScan = 'full';

    scanOptions.forEach(option => {
        option.addEventListener('click', () => {
            scanOptions.forEach(o => o.classList.remove('active'));
            option.classList.add('active');
            selectedScan = option.dataset.scan;
        });
    });

    scanBtn.addEventListener('click', () => performScan());

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performScan();
    });

    async function performScan() {
        const url = urlInput.value.trim();
        if (!url) {
            alert('Please enter a URL to scan');
            return;
        }

        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

        try {
            let endpoint;
            switch(selectedScan) {
                case 'phishing':
                    endpoint = '/scan/phishing';
                    break;
                case 'vulnerability':
                    endpoint = '/scan/vulnerability';
                    break;
                default:
                    endpoint = '/scan/full';
            }

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();
            displayResults(data, selectedScan);
        } catch (error) {
            console.error('Scan error:', error);
            alert('An error occurred during scanning');
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan';
        }
    }

    function displayResults(data, scanType) {
        resultsSection.classList.remove('hidden');
        document.getElementById('scanTime').textContent = `Scan time: ${new Date().toLocaleString()}`;

        if (scanType === 'full') {
            displayFullResults(data);
        } else if (scanType === 'phishing') {
            displayPhishingResults(data);
        } else {
            displayVulnResults(data);
        }

        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    function displayFullResults(data) {
        const phishing = data.phishing;
        const vuln = data.vulnerability;
        const overallRisk = data.overall_risk || 0;

        updateRiskMeter(overallRisk);

        document.getElementById('phishingScore').textContent = `${phishing.risk_score}/100`;
        document.getElementById('phishingLevel').textContent = phishing.risk_level;
        document.getElementById('phishingLevel').className = `value ${phishing.risk_level.toLowerCase()}`;
        document.getElementById('phishingVerdict').textContent = phishing.is_phishing ? '🔴 Phishing Detected' : '🟢 Safe';

        const warningsDiv = document.getElementById('phishingWarnings');
        warningsDiv.innerHTML = '';
        if (phishing.warnings && phishing.warnings.length > 0) {
            phishing.warnings.forEach(w => {
                warningsDiv.innerHTML += `<div class="warning">⚠️ ${w}</div>`;
            });
        }

        document.getElementById('vulnTotal').textContent = vuln.total_vulnerabilities;
        document.getElementById('vulnCritical').textContent = vuln.vulnerability_breakdown?.critical || 0;
        document.getElementById('vulnHigh').textContent = vuln.vulnerability_breakdown?.high || 0;
        document.getElementById('vulnMedium').textContent = vuln.vulnerability_breakdown?.medium || 0;
        document.getElementById('vulnLow').textContent = vuln.vulnerability_breakdown?.low || 0;

        const findingsList = document.getElementById('findingsList');
        findingsList.innerHTML = '';
        if (vuln.findings && vuln.findings.length > 0) {
            vuln.findings.forEach(f => {
                findingsList.innerHTML += `
                    <div class="finding-item ${f.severity}">
                        <div class="finding-title">${f.title}</div>
                        <div class="finding-desc">${f.description}</div>
                    </div>
                `;
            });
        } else {
            findingsList.innerHTML = '<p style="color: var(--text-secondary);">No vulnerabilities found</p>';
        }
    }

    function displayPhishingResults(data) {
        updateRiskMeter(data.risk_score);

        document.getElementById('phishingScore').textContent = `${data.risk_score}/100`;
        document.getElementById('phishingLevel').textContent = data.risk_level;
        document.getElementById('phishingVerdict').textContent = data.is_phishing ? '🔴 Phishing Detected' : '🟢 Safe';

        const warningsDiv = document.getElementById('phishingWarnings');
        warningsDiv.innerHTML = '';
        if (data.warnings && data.warnings.length > 0) {
            data.warnings.forEach(w => {
                warningsDiv.innerHTML += `<div class="warning">⚠️ ${w}</div>`;
            });
        }

        document.getElementById('vulnTotal').textContent = '-';
        document.getElementById('vulnCritical').textContent = '0';
        document.getElementById('vulnHigh').textContent = '0';
        document.getElementById('vulnMedium').textContent = '0';
        document.getElementById('vulnLow').textContent = '0';

        document.getElementById('findingsList').innerHTML = '';
    }

    function displayVulnResults(data) {
        const totalVulns = data.total_vulnerabilities || 0;
        updateRiskMeter(totalVulns * 10);

        document.getElementById('phishingScore').textContent = '-';
        document.getElementById('phishingLevel').textContent = '-';
        document.getElementById('phishingVerdict').textContent = '-';

        document.getElementById('phishingWarnings').innerHTML = '';

        document.getElementById('vulnTotal').textContent = totalVulns;
        document.getElementById('vulnCritical').textContent = data.vulnerability_breakdown?.critical || 0;
        document.getElementById('vulnHigh').textContent = data.vulnerability_breakdown?.high || 0;
        document.getElementById('vulnMedium').textContent = data.vulnerability_breakdown?.medium || 0;
        document.getElementById('vulnLow').textContent = data.vulnerability_breakdown?.low || 0;

        const findingsList = document.getElementById('findingsList');
        findingsList.innerHTML = '';
        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(f => {
                findingsList.innerHTML += `
                    <div class="finding-item ${f.severity}">
                        <div class="finding-title">${f.title}</div>
                        <div class="finding-desc">${f.description}</div>
                    </div>
                `;
            });
        } else {
            findingsList.innerHTML = '<p style="color: var(--text-secondary);">No vulnerabilities found</p>';
        }
    }

    function updateRiskMeter(score) {
        const fill = document.getElementById('riskFill');
        const scoreDisplay = document.getElementById('riskScore');
        const normalizedScore = Math.min(Math.max(score, 0), 100);

        fill.style.width = normalizedScore + '%';
        scoreDisplay.textContent = normalizedScore + '/100';

        if (normalizedScore < 30) {
            fill.style.background = 'var(--success)';
        } else if (normalizedScore < 60) {
            fill.style.background = 'var(--warning)';
        } else {
            fill.style.background = 'var(--danger)';
        }
    }
});
