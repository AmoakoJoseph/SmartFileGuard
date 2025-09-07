// Main JavaScript functionality for SmartFileGuard

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize file upload
    initializeFileUpload();
    
    // Initialize URL validation
    initializeUrlValidation();
    
    // Initialize auto-refresh
    initializeAutoRefresh();
    
    // Initialize notification system
    initializeNotifications();
}

// Tooltip initialization
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// File upload functionality
function initializeFileUpload() {
    const fileInput = document.getElementById('fileInput');
    const uploadArea = document.getElementById('uploadArea');
    const fileList = document.getElementById('fileList');
    const uploadBtn = document.getElementById('uploadBtn');
    
    if (!fileInput || !uploadArea) return;
    
    // Drag and drop handlers
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });
    
    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, unhighlight, false);
    });
    
    uploadArea.addEventListener('drop', handleDrop, false);
    
    // Handle click on upload area (but not on the button)
    uploadArea.addEventListener('click', (e) => {
        if (e.target.id !== 'selectFilesBtn' && !e.target.closest('#selectFilesBtn')) {
            fileInput.click();
        }
    });
    
    // Handle click on select files button
    const selectFilesBtn = document.getElementById('selectFilesBtn');
    if (selectFilesBtn) {
        selectFilesBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }
    
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    function highlight() {
        uploadArea.classList.add('dragover');
    }
    
    function unhighlight() {
        uploadArea.classList.remove('dragover');
    }
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        fileInput.files = files;
        handleFileSelect();
    }
    
    function handleFileSelect() {
        const files = fileInput.files;
        if (fileList && uploadBtn) {
            updateFileList(files);
            uploadBtn.disabled = files.length === 0;
        }
    }
    
    function updateFileList(files) {
        if (!fileList) return;
        
        fileList.innerHTML = '';
        
        if (files.length === 0) return;
        
        const listGroup = document.createElement('div');
        listGroup.className = 'list-group';
        
        Array.from(files).forEach((file, index) => {
            const item = createFileListItem(file, index);
            listGroup.appendChild(item);
        });
        
        fileList.appendChild(listGroup);
    }
    
    function createFileListItem(file, index) {
        const item = document.createElement('div');
        item.className = 'list-group-item d-flex justify-content-between align-items-center';
        
        const fileSize = formatFileSize(file.size);
        const fileIcon = getFileIcon(file.name);
        
        item.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas fa-${fileIcon} me-2"></i>
                <div>
                    <div class="fw-bold">${escapeHtml(file.name)}</div>
                    <small class="text-muted">${fileSize}</small>
                </div>
            </div>
            <div>
                <span class="badge bg-primary">Ready</span>
                <button type="button" class="btn btn-sm btn-outline-danger ms-2" 
                        onclick="removeFile(${index})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        return item;
    }
}

// URL validation
function initializeUrlValidation() {
    const urlForm = document.getElementById('urlScanForm');
    const urlInput = document.getElementById('url');
    
    if (!urlForm || !urlInput) return;
    
    urlInput.addEventListener('input', function() {
        validateUrl(this.value);
    });
    
    urlForm.addEventListener('submit', function(e) {
        const url = urlInput.value.trim();
        if (!isValidUrl(url)) {
            e.preventDefault();
            showNotification('Please enter a valid URL', 'error');
        }
    });
}

// Auto-refresh functionality
function initializeAutoRefresh() {
    // Auto-refresh certain pages
    const currentPath = window.location.pathname;
    const refreshPages = ['/monitoring', '/quarantine'];
    
    if (refreshPages.some(page => currentPath.includes(page))) {
        setInterval(() => {
            if (document.visibilityState === 'visible') {
                refreshPageData();
            }
        }, 30000); // 30 seconds
    }
}

// Notification system
function initializeNotifications() {
    // Check for system notifications
    checkSystemStatus();
    
    // Set up periodic status checks
    setInterval(checkSystemStatus, 60000); // 1 minute
}

// Utility functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getFileIcon(filename) {
    const extension = filename.split('.').pop().toLowerCase();
    const iconMap = {
        'pdf': 'file-pdf',
        'doc': 'file-word',
        'docx': 'file-word',
        'xls': 'file-excel',
        'xlsx': 'file-excel',
        'ppt': 'file-powerpoint',
        'pptx': 'file-powerpoint',
        'zip': 'file-archive',
        'rar': 'file-archive',
        '7z': 'file-archive',
        'exe': 'file-code',
        'dll': 'file-code',
        'js': 'file-code',
        'jar': 'file-code'
    };
    
    return iconMap[extension] || 'file-alt';
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

function isValidUrl(string) {
    try {
        new URL(string);
        return string.startsWith('http://') || string.startsWith('https://');
    } catch (_) {
        return false;
    }
}

function validateUrl(url) {
    const urlInput = document.getElementById('url');
    if (!urlInput) return;
    
    if (url && !isValidUrl(url)) {
        urlInput.classList.add('is-invalid');
    } else {
        urlInput.classList.remove('is-invalid');
    }
}

function removeFile(index) {
    const fileInput = document.getElementById('fileInput');
    if (!fileInput) return;
    
    const dt = new DataTransfer();
    const files = Array.from(fileInput.files);
    
    files.forEach((file, i) => {
        if (i !== index) {
            dt.items.add(file);
        }
    });
    
    fileInput.files = dt.files;
    fileInput.dispatchEvent(new Event('change'));
}

function showNotification(message, type = 'info') {
    const alertContainer = document.createElement('div');
    alertContainer.className = 'position-fixed top-0 end-0 p-3';
    alertContainer.style.zIndex = '1055';
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
    alert.innerHTML = `
        <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
        ${escapeHtml(message)}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    alertContainer.appendChild(alert);
    document.body.appendChild(alertContainer);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertContainer.parentNode) {
            alertContainer.remove();
        }
    }, 5000);
}

function refreshPageData() {
    // Simple page refresh for now
    // In a real application, this would use AJAX to update specific sections
    if (document.hidden) return;
    
    const refreshIndicator = document.createElement('div');
    refreshIndicator.className = 'position-fixed top-0 start-50 translate-middle-x p-2';
    refreshIndicator.style.zIndex = '1060';
    refreshIndicator.innerHTML = `
        <div class="badge bg-info">
            <i class="fas fa-sync-alt fa-spin me-1"></i>
            Updating...
        </div>
    `;
    
    document.body.appendChild(refreshIndicator);
    
    setTimeout(() => {
        location.reload();
    }, 1000);
}

function checkSystemStatus() {
    // Simulate system status check
    // In a real application, this would make an API call
    const statusIndicator = document.querySelector('.navbar-text');
    if (statusIndicator) {
        // Update status indicator
        const isOnline = navigator.onLine;
        const statusIcon = statusIndicator.querySelector('i');
        const statusText = statusIndicator;
        
        if (isOnline) {
            statusIcon.className = 'fas fa-shield-alt text-success me-1';
            statusText.innerHTML = '<i class="fas fa-shield-alt text-success me-1"></i> System Active';
        } else {
            statusIcon.className = 'fas fa-exclamation-triangle text-warning me-1';
            statusText.innerHTML = '<i class="fas fa-exclamation-triangle text-warning me-1"></i> Connection Issues';
        }
    }
}

// Form submission handlers
function handleFormSubmission(formId, loadingText = 'Processing...') {
    const form = document.getElementById(formId);
    if (!form) return;
    
    form.addEventListener('submit', function() {
        const submitBtn = this.querySelector('button[type="submit"]');
        if (submitBtn) {
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin me-1"></i> ${loadingText}`;
            submitBtn.disabled = true;
            
            // Re-enable button after a delay (in case form submission fails)
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            }, 30000);
        }
    });
}

// Initialize form handlers
document.addEventListener('DOMContentLoaded', function() {
    handleFormSubmission('fileUploadForm', 'Scanning...');
    handleFormSubmission('urlScanForm', 'Analyzing...');
});

// Progress bar animations
function animateProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = width;
        }, 100);
    });
}

// Call on page load
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(animateProgressBars, 500);
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+U for upload
    if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        const fileInput = document.getElementById('fileInput');
        if (fileInput) fileInput.click();
    }
    
    // Ctrl+R for refresh (override default)
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        location.reload();
    }
});

// Export functions for global use
window.SmartFileGuard = {
    showNotification,
    formatFileSize,
    isValidUrl,
    refreshPageData,
    checkSystemStatus
};
