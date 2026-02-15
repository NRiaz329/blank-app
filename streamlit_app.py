<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verifier Pro - Single & Bulk Email Verification</title>
    <link rel="stylesheet" href="style.css">
    <link rel="shortcut icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='75' font-size='75' fill='%236366f1'>✉</text></svg>">
</head>
<body>
    <div class="container">
        <!-- Navigation -->
        <nav class="navbar">
            <div class="navbar-content">
                <div class="navbar-brand">
                    <span class="brand-icon">✉️</span>
                    <h1>Email Verifier Pro</h1>
                </div>
                <ul class="navbar-menu">
                    <li><a href="#single-verify" class="nav-link active" onclick="switchTab('single')">Single Verify</a></li>
                    <li><a href="#bulk-verify" class="nav-link" onclick="switchTab('bulk')">Bulk Verify</a></li>
                    <li><a href="#statistics" class="nav-link" onclick="switchTab('stats')">Statistics</a></li>
                    <li><a href="#settings" class="nav-link" onclick="switchTab('settings')">Settings</a></li>
                </ul>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Single Email Verification Tab -->
            <div id="single-verify" class="tab-content active">
                <div class="card">
                    <div class="card-header">
                        <h2>Single Email Verification</h2>
                        <p>Verify a single email address with detailed analysis</p>
                    </div>
                    
                    <div class="card-body">
                        <div class="form-group">
                            <label for="email-input">Email Address</label>
                            <div class="input-group">
                                <input 
                                    type="email" 
                                    id="email-input" 
                                    class="form-input"
                                    placeholder="example@company.com"
                                    onkeypress="if(event.key === 'Enter') verifySingle()"
                                >
                                <button class="btn btn-primary" onclick="verifySingle()">
                                    <span class="btn-text">Verify</span>
                                    <span class="btn-loader" id="verify-loader" style="display:none;">⏳</span>
                                </button>
                            </div>
                            <small class="form-help">Enter a valid email address to start verification</small>
                        </div>

                        <!-- Verification Result -->
                        <div id="result-container" class="result-container" style="display:none;">
                            <div class="result-header">
                                <h3>Verification Result</h3>
                                <span class="result-status" id="result-status"></span>
                            </div>

                            <div class="result-grid">
                                <!-- Left Column -->
                                <div class="result-column">
                                    <div class="result-item">
                                        <span class="result-label">Email</span>
                                        <span class="result-value" id="result-email">-</span>
                                    </div>

                                    <div class="result-item">
                                        <span class="result-label">Status</span>
                                        <span class="result-value" id="result-email-status">-</span>
                                    </div>

                                    <div class="result-item">
                                        <span class="result-label">SMTP Code</span>
                                        <span class="result-value" id="result-smtp-code">-</span>
                                    </div>

                                    <div class="result-item">
                                        <span class="result-label">Disposable Email</span>
                                        <span class="result-value" id="result-disposable">-</span>
                                    </div>
                                </div>

                                <!-- Right Column -->
                                <div class="result-column">
                                    <div class="result-item">
                                        <span class="result-label">Catch-All Domain</span>
                                        <span class="result-value" id="result-catchall">-</span>
                                    </div>

                                    <div class="result-item">
                                        <span class="result-label">Role-Based Email</span>
                                        <span class="result-value" id="result-rolebased">-</span>
                                    </div>

                                    <div class="result-item">
                                        <span class="result-label">SMTP Response Time</span>
                                        <span class="result-value" id="result-smtp-time">-</span>
                                    </div>

                                    <div class="result-item">
                                        <span class="result-label">Confidence</span>
                                        <span class="result-value" id="result-confidence">-</span>
                                    </div>
                                </div>
                            </div>

                            <!-- Risk Score -->
                            <div class="risk-score-
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --color-primary: #6366f1;
    --color-primary-dark: #4f46e5;
    --color-success: #10b981;
    --color-warning: #f59e0b;
    --color-danger: #ef4444;
    --color-info: #3b82f6;
    
    --bg-primary: #1f2937;
    --bg-secondary: #111827;
    --bg-tertiary: #374151;
    
    --text-primary: #f3f4f6;
    --text-secondary: #d1d5db;
    --text-tertiary: #9ca3af;
    
    --border-color: #4b5563;
    
    --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.5);
    --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.5);
    --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.5);
    
    --radius-sm: 4px;
    --radius-md: 8px;
    --radius-lg: 12px;
    
    --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

body.light-theme {
    --color-primary: #6366f1;
    --color-primary-dark: #4f46e5;
    --color-success: #10b981;
    --color-warning: #f59e0b;
    --color-danger: #ef4444;
    --color-info: #3b82f6;
    
    --bg-primary: #ffffff;
    --bg-secondary: #f9fafb;
    --bg-tertiary: #f3f4f6;
    
    --text-primary: #1f2937;
    --text-secondary: #4b5563;
    --text-tertiary: #9ca3af;
    
    --border-color: #e5e7eb;
    
    --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
    --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
    --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.15);
}

html {
    scroll-behavior: smooth;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
    background-color: var(--bg-secondary);
    color: var(--text-primary);
    line-height: 1.6;
    transition: var(--transition);
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Navigation */
.navbar {
    background-color: var(--bg-primary);
    border-bottom: 1px solid var(--border-color);
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: var(--shadow-md);
}

.navbar-content {
    max-width: 1400px;
    margin: 0 auto;
    padding: 0 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    height: 70px;
}

.navbar-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    text-decoration: none;
    color: var(--text-primary);
}

.brand-icon {
    font-size: 28px;
}

.navbar-brand h1 {
    font-size: 20px;
    font-weight: 700;
    background: linear-gradient(135deg, var(--color-primary), var(--color-info));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.navbar-menu {
    display: flex;
    list-style: none;
    gap: 30px;
}

.nav-link {
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 500;
    padding: 8px 12px;
    border-bottom: 2px solid transparent;
    transition: var(--transition);
    cursor: pointer;
}

.nav-link:hover,
.nav-link.active {
    color: var(--color-primary);
    border-bottom-color: var(--color-primary);
}

/* Main Content */
.main-content {
    flex: 1;
    padding: 40px 20px;
    max-width: 1400px;
    width: 100%;
    margin: 0 auto;
}

.tab-content {
    display: none;
    animation: fadeIn 0.3s ease-in;
}

.tab-content.active {
    display: block;
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* Cards */
.card {
    background-color: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
    overflow: hidden;
    transition: var(--transition);
}

.card:hover {
    box-shadow: var(--shadow-lg);
}

.card-header {
    padding: 30px;
    border-bottom: 1px solid var(--border-color);
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(59, 130, 246, 0.1));
}

.card-header h2 {
    font-size: 28px;
    margin-bottom: 8px;
    color: var(--text-primary);
}

.card-header p {
    color: var(--text-secondary);
    font-size: 14px;
}

.card-body {
    padding: 30px;
}

/* Forms */
.form-group {
    margin-bottom: 24px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: var(--text-primary);
}

.form-input,
.form-input select {
    width: 100%;
    padding: 12px 16px;
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    font-size: 14px;
    transition: var(--transition);
}

.form-input:focus,
.form-input select:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
}

.form-help {
    display: block;
    margin-top: 6px;
    color: var(--text-tertiary);
    font-size: 12px;
}

.input-group {
    display: flex;
    gap: 10px;
}

.input-group .form-input {
    flex: 1;
    margin-bottom: 0;
}

.form-group.checkbox {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
}

.form-group.checkbox input[type="checkbox"] {
    width: 20px;
    height: 20px;
    cursor: pointer;
    accent-color: var(--color-primary);
}

.form-group.checkbox label {
    margin-bottom: 0;
    cursor: pointer;
    font-weight: 500;
}

/* Buttons */
.btn {
    padding: 10px 20px;
    border: none;
    border-radius: var(--radius-md);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: var(--transition);
    display: inline-flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
}

.btn:active {
    transform: translateY(0);
}

.btn-primary {
    background-color: var(--color-primary);
    color: white;
}

.btn-primary:hover {
    background-color: var(--color-primary-dark);
}

.btn-secondary {
    background-color: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
}

.btn-secondary:hover {
    background-color: var(--border-color);
}

.btn-sm {
    padding: 6px 12px;
    font-size: 12px;
}

.btn-lg {
    padding: 14px 28px;
    font-size: 16px;
}

.btn-loader {
    display: inline-block;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

/* Single Verification */
.result-container {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.05), rgba(59, 130, 246, 0.05));
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 24px;
    margin-top: 30px;
}

.result-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border-color);
}

.result-header h3 {
    font-size: 20px;
    color: var(--text-primary);
}

.result-status {
    padding: 6px 12px;
    border-radius: var(--radius-md);
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.result-status.valid {
    background-color: rgba(16, 185, 129, 0.2);
    color: var(--color-success);
}

.result-status.invalid {
    background-color: rgba(239, 68, 68, 0.2);
    color: var(--color-danger);
}

.result-status.warning {
    background-color: rgba(245, 158, 11, 0.2);
    color: var(--color-warning);
}

.result-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
    margin-bottom: 30px;
}

@media (max-width: 768px) {
    .result-grid {
        grid-template-columns: 1fr;
    }
}

.result-column {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.result-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0;
    border-bottom: 1px solid var(--border-color);
}

.result-item:last-child {
    border-bottom: none;
}

.result-label {
    color: var(--text-secondary);
    font-weight: 500;
}

.result-value {
    color: var(--text-primary);
    font-weight: 600;
    text-align: right;
}

.result-value.success {
    color: var(--color-success);
}

.result-value.danger {
    color: var(--color-danger);
}

.result-value.warning {
    color: var(--color-warning);
}

/* Risk Score */
.risk-score-section {
    margin: 30px 0;
    padding: 24px 0;
    border-top: 1px solid var(--border-color);
    border-bottom: 1px solid var(--border-color);
}

.risk-score-container {
    text-align: center;
}

.risk-score-container h4 {
    margin-bottom: 20px;
    color: var(--text-primary);
}

.risk-score-display {
    display: flex;
    justify-content: center;
    align-items: center;
    margin-bottom: 20px;
    position: relative;
    width: 150px;
    height: 150px;
    margin-left: auto;
    margin-right: auto;
}

.risk-circle {
    width: 100%;
    height: 100%;
    transform: rotate(-90deg);
}

.risk-bg {
    fill: none;
    stroke: var(--bg-tertiary);
    stroke-width: 8;
}

.risk-progress {
    fill: none;
    stroke: url(#riskGradient);
    stroke-width: 8;
    stroke-linecap: round;
    stroke-dasharray: 339.292;
    stroke-dashoffset: 339.292;
    transition: stroke-dashoffset 0.5s ease;
}

.risk-text {
    position: absolute;
    display: flex;
    flex-direction: column;
    align-items: center;
}

.risk-score-value {
    font-size: 32px;
    font-weight: 700;
    color: var(--text-primary);
}

.risk-score-label {
    font-size: 12px;
    color: var(--text-tertiary);
}

.risk-interpretation {
    color: var(--text-secondary);
    font-size: 14px;
    margin-top: 10px;
}

/* Details */
.details-section {
    margin-top: 24px;
}

.details-section h4 {
    margin-bottom: 16px;
    color: var(--text-primary);
}

.details-list {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.details-list li {
    padding: 8px 12px;
    background-color: var(--bg-secondary);
    border-left: 3px solid var(--color-primary);
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    font-size: 13px;
}

.details-list li.success {
    border-left-color: var(--color-success);
    background-color: rgba(16, 185, 129, 0.1);
}

.details-list li.warning {
    border-left-color: var(--color-warning);
    background-color: rgba(245, 158, 11, 0.1);
}

.details-list li.error {
    border-left-color: var(--color-danger);
    background-color: rgba(239, 68, 68, 0.1);
}

/* Error Message */
.error-message {
    background-color: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: var(--radius-md);
    padding: 16px;
    color: var(--color-danger);
    font-size: 14px;
}

/* Loading State */
.loading-container {
    text-align: center;
    padding: 60px 20px;
}

.spinner {
    width: 50px;
    height: 50px;
    border: 4px solid var(--bg-tertiary);
    border-top-color: var(--color-primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
}

.loading-container p {
    color: var(--text-secondary);
}

/* No Result State */
.no-result-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-tertiary);
}

.empty-illustration {
    font-size: 64px;
    margin-bottom: 20px;
}

/* Bulk Upload */
.upload-section {
    margin-bottom: 30px;
}

.upload-area {
    border: 2px dashed var(--border-color);
    border-radius: var(--radius-lg);
    padding: 60px 20px;
    text-align: center;
    cursor: pointer;
    transition: var(--transition);
}

.upload-area:hover,
.upload-area.dragover {
    border-color: var(--color-primary);
    background-color: rgba(99, 102, 241, 0.05);
}

.upload-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
}

.upload-icon {
    font-size: 48px;
}

.upload-area h3 {
    margin: 0;
    color: var(--text-primary);
}

.upload-area p {
    color: var(--text-secondary);
    margin: 0;
}

.upload-area small {
    color: var(--text-tertiary);
}

/* File Info */
.file-info {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 16px;
    margin: 20px 0;
}

.info-item {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
}

.info-label {
    color: var(--text-secondary);
    font-weight: 500;
}

.info-value {
    color: var(--text-primary);
    font-weight: 600;
}

/* Progress Section */
.progress-section {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.05), rgba(59, 130, 246, 0.05));
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 24px;
    margin-top: 30px;
}

.progress-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.progress-header h3 {
    color: var(--text-primary);
    margin: 0;
}

.progress-percentage {
    font-weight: 700;
    color: var(--color-primary);
    font-size: 18px;
}

.progress-bar-container {
    width: 100%;
    height: 8px;
    background-color: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 20px;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, var(--color-primary), var(--color-info));
    width: 0%;
    transition: width 0.3s ease;
    border-radius: 4px;
}

.progress-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}

.stat {
    background-color: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 16px;
    text-align: center;
}

.stat-label {
    display: block;
    color: var(--text-secondary);
    font-size: 12px;
    margin-bottom: 6px;
}

.stat-value {
    display: block;
    font-size: 24px;
    font-weight: 700;
    color: var(--text-primary);
}

.stat-value.valid {
    color: var(--color-success);
}

.stat-value.invalid {
    color: var(--color-danger);
}

/* Results Table */
.results-table-container {
    margin-top: 24px;
}

.results-table-container h4 {
    margin-bottom: 16px;
    color: var(--text-primary);
}

.results-table {
    width: 100%;
    border-collapse: collapse;
}

.results-table thead {
    background-color: var(--bg-secondary);
}

.results-table th {
    padding: 12px;
    text-align: left;
    font-weight: 600;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border-color);
}

.results-table td {
    padding: 12px;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-primary);
}

.results-table tbody tr:hover {
    background-color: var(--bg-secondary);
}

.results-table .status-badge {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
}

.results-table .status-valid {
    background-color: rgba(16, 185, 129, 0.2);
    color: var(--color-success);
}

.results-table .status-invalid {
    background-color: rgba(239, 68, 68, 0.2);
    color: var(--color-danger);
}

/* CSV Helper */
.csv-helper {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 20px;
    margin-top: 30px;
}

.csv-helper h4 {
    margin-bottom: 12px;
    color: var(--text-primary);
}

.csv-helper p {
    color: var(--text-secondary);
    margin-bottom: 12px;
    font-size: 13px;
}

.csv-helper pre {
    background-color: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-sm);
    padding: 12px;
    overflow-x: auto;
    color: var(--color-info);
    font-size: 12px;
}

/* Statistics Cards */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}

.stat-card {
    background: linear-gradient(135deg, var(--bg-primary), var(--bg-secondary));
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 24px;
    display: flex;
    gap: 16px;
    align-items: flex-start;
    transition: var(--transition);
}

.stat-card:hover {
    border-color: var(--color-primary);
    box-shadow: var(--shadow-md);
    transform: translateY(-4px);
}

.stat-card-icon {
    font-size: 32px;
}

.stat-card-content {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.stat-card-label {
    color: var(--text-secondary);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-card-value {
    font-size: 24px;
    font-weight: 700;
    color: var(--text-primary);
}

.stat-card-percentage {
    color: var(--color-primary);
    font-weight: 600;
    font-size: 12px;
}

/* Settings */
.settings-section {
    margin-bottom: 32px;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--border-color);
}

.settings-section:last-of-type {
    border-bottom: none;
}

.settings-section h3 {
    margin-bottom: 20px;
    color: var(--text-primary);
}

.settings-actions {
    display: flex;
    gap: 12px;
    margin-top: 30px;
}

/* Notifications */
.notification-toast {
    position: fixed;
    bottom: 30px;
    right: 30px;
    background-color: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 16px 20px;
    box-shadow: var(--shadow-lg);
    color: var(--text-primary);
    z-index: 1000;
    animation: slideIn 0.3s ease;
    max-width: 400px;
    display: none;
}

.notification-toast.success {
    border-left: 4px solid var(--color-success);
}

.notification-toast.error {
    border-left: 4px solid var(--color-danger);
}

.notification-toast.warning {
    border-left: 4px solid var(--color-warning);
}

.notification-toast.show {
    display: block;
}

@keyframes slideIn {
    from {
        transform: translateX(400px);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

/* Footer */
.footer {
    background-color: var(--bg-primary);
    border-top: 1px solid var(--border-color);
    padding: 30px 20px;
    text-align: center;
    color: var(--text-tertiary);
    font-size: 13px;
    margin-top: 60px;
}

.footer p {
    margin: 4px 0;
}

/* Responsive Design */
@media (max-width: 768px) {
    .navbar-content {
        flex-direction: column;
        height: auto;
        padding: 10px 20px;
        gap: 10px;
    }

    .navbar-menu {
        width: 100%;
        flex-wrap: wrap;
        justify-content: center;
        gap: 15px;
    }

    .navbar-brand h1 {
        font-size: 18px;
    }

    .card-header {
        padding: 20px;
    }

    .card-body {
        padding: 20px;
    }

    .main-content {
        padding: 20px 10px;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }

    .result-grid {
        grid-template-columns: 1fr;
    }

    .input-group {
        flex-direction: column;
    }

    .settings-actions {
        flex-direction: column;
    }

    .settings-actions .btn {
        width: 100%;
    }

    .notification-toast {
        right: 20px;
        left: 20px;
        bottom: 20px;
    }
}

@media (prefers-color-scheme: light) {
    body.light-theme {
        color-scheme: light;
    }
}

