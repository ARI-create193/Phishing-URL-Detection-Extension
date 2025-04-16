document.addEventListener('DOMContentLoaded', function() {
  // Tab switching
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabId = button.getAttribute('data-tab');
      
      // Update active tab button
      tabButtons.forEach(btn => btn.classList.remove('active'));
      button.classList.add('active');
      
      // Show active tab content
      tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === tabId) {
          content.classList.add('active');
        }
      });
      
      // Load detections if history tab
      if (tabId === 'history') {
        loadDetections();
      }
    });
  });
  
  // Load settings
  loadSettings();
  
  // Analyze URL button click
  document.getElementById('analyze-btn').addEventListener('click', function() {
    const url = document.getElementById('url-input').value.trim();
    if (url) {
      showLoading(true);
      analyzeUrl(url);
    }
  });
  
  // Analyze current page button click
  document.getElementById('analyze-current-btn').addEventListener('click', function() {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs && tabs[0] && tabs[0].url) {
        const url = tabs[0].url;
        document.getElementById('url-input').value = url;
        showLoading(true);
        analyzeUrl(url);
      }
    });
  });
  
  // Clear history button click
  document.getElementById('clear-history').addEventListener('click', function() {
    chrome.runtime.sendMessage({ action: "clearDetections" }, function() {
      loadDetections();
    });
  });
  
  // Save settings when changed
  document.getElementById('real-time-protection').addEventListener('change', saveSettings);
  document.getElementById('show-warnings').addEventListener('change', saveSettings);
  document.getElementById('check-domain-age').addEventListener('change', saveSettings);
  document.getElementById('advanced-analysis').addEventListener('change', saveSettings);
  document.getElementById('sensitivity-slider').addEventListener('change', saveSettings);

  // Loading indicator
  function showLoading(show) {
    const loadingDiv = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    
    if (show) {
      loadingDiv.style.display = 'block';
      resultDiv.style.display = 'none';
    } else {
      loadingDiv.style.display = 'none';
    }
  }
  
  // Analyze URL function
  function analyzeUrl(url) {
    chrome.runtime.sendMessage({ 
      action: "analyzeUrl", 
      url: url,
      checkDomainAge: document.getElementById('check-domain-age').checked
    }, function(response) {
      showLoading(false);
      displayResult(response);
    });
  }
  
  // Check domain age function
  function checkDomainAge(domain) {
    return new Promise((resolve) => {
      // Simulate domain age check
      // In a real implementation, this would call a WHOIS API service
      setTimeout(() => {
        // Random domain age for demo purposes
        const ageInDays = Math.floor(Math.random() * 3650); // 0-10 years
        resolve({
          domain: domain,
          ageInDays: ageInDays,
          registrationDate: new Date(Date.now() - ageInDays * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          isSuspicious: ageInDays < 30 // Domains less than 30 days old are flagged
        });
      }, 300);
    });
  }
  
  // Display result function
  function displayResult(result) {
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = 'block';
    resultDiv.className = 'result ' + result.classification.toLowerCase();
    
    // Extract risk factors
    const explanationText = result.explanation;
    let riskFactorsHTML = '';
    
    if (explanationText.includes('Risk Factors Detected:')) {
      const riskFactorsSection = explanationText.split('Risk Factors Detected:')[1];
      if (riskFactorsSection) {
        const riskFactors = riskFactorsSection.split('\n').filter(line => line.trim().startsWith('-'));
        
        if (riskFactors.length > 0) {
          riskFactorsHTML = `
            <div class="risk-factors">
              <div class="domain-age-title">Risk Factors:</div>
              ${riskFactors.map(factor => `
                <div class="risk-factor-item">
                  <span class="risk-indicator"></span>
                  ${factor.replace('-', '').trim()}
                </div>
              `).join('')}
            </div>
          `;
        }
      }
    }
    
    // Domain age section
    let domainAgeHTML = '';
    if (result.domainAge) {
      const ageStatus = result.domainAge.isSuspicious ? 
        '<span style="color: var(--danger-color);">New Domain (Suspicious)</span>' : 
        '<span style="color: var(--success-color);">Established Domain</span>';
      
      domainAgeHTML = `
        <div class="domain-age">
          <div class="domain-age-title">Domain Age:</div>
          <div>${result.domainAge.ageInDays} days (Registered: ${result.domainAge.registrationDate})</div>
          <div>Status: ${ageStatus}</div>
        </div>
      `;
    }
    
    // Build extracted features HTML
    let featuresHTML = '';
    if (result.urlInfo) {
      featuresHTML = `
        <div class="domain-age" style="margin-top: 12px;">
          <div class="domain-age-title">Extracted Features:</div>
          <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Domain:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.domain}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Domain Length:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.domainLength} characters</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Path Length:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.pathLength} characters</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Number of Dots:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.numDots}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Number of Hyphens:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.numHyphens}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Number of @ Symbols:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.numAtSymbols}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Number of = Symbols:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.numEquals}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Number of Digits:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.numDigits}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Subdomain Levels:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.subdomainLevels}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">Has Suspicious Words:</td>
              <td style="padding: 3px 0; border-bottom: 1px solid var(--border-color);">${result.urlInfo.hasSuspiciousWords ? 'Yes' : 'No'}</td>
            </tr>
            <tr>
              <td style="padding: 3px 0;">Has IP Address:</td>
              <td style="padding: 3px 0;">${result.urlInfo.hasIpAddress ? 'Yes' : 'No'}</td>
            </tr>
          </table>
        </div>
      `;
    }
    
    // Build the result HTML
    resultDiv.innerHTML = `
      <h2>${result.classification}</h2>
      <div class="confidence">Confidence: ${(result.confidence * 100).toFixed(2)}%</div>
      <div class="explanation">
        Analysis of: ${result.url}
        ${domainAgeHTML}
        ${featuresHTML}
        ${riskFactorsHTML}
      </div>
    `;
  }
  
  // Load detection history
  function loadDetections() {
    chrome.runtime.sendMessage({ action: "getDetections" }, function(detections) {
      const detectionsListDiv = document.getElementById('detections-list');
      
      if (!detections || detections.length === 0) {
        detectionsListDiv.innerHTML = '<div class="no-detections">No detections yet.</div>';
        return;
      }
      
      detectionsListDiv.innerHTML = '';
      
      // Sort by timestamp (newest first)
      detections.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      
      detections.forEach(detection => {
        const detectionDiv = document.createElement('div');
        detectionDiv.className = 'detection-item';
        
        const date = new Date(detection.timestamp);
        const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        
        detectionDiv.innerHTML = `
          <div class="detection-url">${detection.url}</div>
          <div class="detection-time">${formattedDate}</div>
          <div class="detection-result ${detection.classification.toLowerCase()}">${detection.classification}</div>
          <div>Confidence: ${(detection.confidence * 100).toFixed(2)}%</div>
          ${detection.domainAge ? `
            <div style="margin-top: 8px; font-size: 12px;">
              Domain Age: ${detection.domainAge.ageInDays} days
              (${detection.domainAge.isSuspicious ? 'Suspicious' : 'Established'})
            </div>
          ` : ''}
        `;
        
        detectionsListDiv.appendChild(detectionDiv);
      });
    });
  }
  
  // Load settings from storage
  function loadSettings() {
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {
        realTimeProtection: true,
        showWarnings: true,
        checkDomainAge: true,
        advancedAnalysis: true,
        sensitivityLevel: 3
      };
      
      document.getElementById('real-time-protection').checked = settings.realTimeProtection;
      document.getElementById('show-warnings').checked = settings.showWarnings;
      document.getElementById('check-domain-age').checked = settings.checkDomainAge;
      document.getElementById('advanced-analysis').checked = settings.advancedAnalysis;
      document.getElementById('sensitivity-slider').value = settings.sensitivityLevel;
    });
  }
  
  // Save settings to storage
  function saveSettings() {
    const settings = {
      realTimeProtection: document.getElementById('real-time-protection').checked,
      showWarnings: document.getElementById('show-warnings').checked,
      checkDomainAge: document.getElementById('check-domain-age').checked,
      advancedAnalysis: document.getElementById('advanced-analysis').checked,
      sensitivityLevel: parseInt(document.getElementById('sensitivity-slider').value)
    };
    
    chrome.storage.local.set({ settings });
    
    // Send updated settings to background script
    chrome.runtime.sendMessage({ action: "updateSettings", settings });
  }
  
  // Load current page URL on popup open
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith('http')) {
      document.getElementById('url-input').value = tabs[0].url;
    }
  });
});