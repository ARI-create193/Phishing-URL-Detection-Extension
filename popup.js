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
      } else if (tabId === 'statistics') {
        loadStatistics();
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
  document.getElementById('monitor-suspicious-tlds').addEventListener('change', saveSettings);
  document.getElementById('sensitivity-level').addEventListener('change', saveSettings);
  
  // Refresh statistics button click
  document.getElementById('refresh-stats').addEventListener('click', function() {
    loadStatistics();
  });

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
      checkDomainAge: document.getElementById('check-domain-age').checked,
      sensitivityLevel: parseInt(document.getElementById('sensitivity-level').value)
    }, function(response) {
      showLoading(false);
      displayResult(response);
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
    
    // Add domain category
    let categoryHTML = '';
    if (result.urlInfo && result.urlInfo.category) {
      // Get category icon
      let categoryIcon = '💻'; // Default tech icon
      switch(result.urlInfo.category) {
        case 'education': categoryIcon = '🎓'; break;
        case 'ecommerce': categoryIcon = '🛒'; break;
        case 'social': categoryIcon = '👥'; break;
        case 'financial': categoryIcon = '🏦'; break;
        case 'gaming': categoryIcon = '🎮'; break;
        case 'streaming': categoryIcon = '🎬'; break;
        case 'technology': categoryIcon = '💻'; break;
        case 'government': categoryIcon = '🏛️'; break;
        case 'healthcare': categoryIcon = '🏥'; break;
        case 'news': categoryIcon = '📰'; break;
      }
      
      const categoryName = result.urlInfo.category.charAt(0).toUpperCase() + result.urlInfo.category.slice(1);
      categoryHTML = `
        <div style="margin-top: 8px;">
          <span class="domain-category">
            <span class="category-icon">${categoryIcon}</span>${categoryName}
          </span>
        </div>
      `;
    }
    
    // Check for suspicious TLD
    let tldHTML = '';
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
      '.date', '.bid', '.stream', '.download', '.loan'];
    
    if (result.urlInfo && result.urlInfo.domain) {
      const domain = result.urlInfo.domain.toLowerCase();
      const hasSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));
      
      if (hasSuspiciousTLD && document.getElementById('monitor-suspicious-tlds').checked) {
        tldHTML = `
          <span class="suspicious-tld">
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
              <line x1="12" y1="9" x2="12" y2="13"></line>
              <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
            Suspicious TLD
          </span>
        `;
      }
    }
    
    // Add phishing count information if available
    let phishingCountHTML = '';
    if (result.phishingCount && result.phishingCount > 0) {
      phishingCountHTML = `
        <div style="margin-top: 8px; padding: 8px; background-color: ${result.phishingCount > 1 ? 'rgba(234, 67, 53, 0.1)' : 'rgba(251, 188, 5, 0.1)'}; border-radius: 4px;">
          <div style="font-weight: 500;">Previous Detections:</div>
          <div>This domain has been detected in ${result.phishingCount} phishing attempts.</div>
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
        ${categoryHTML}
        ${tldHTML}
        ${phishingCountHTML}
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
        
        // Get category icon
        let categoryIcon = '💻'; // Default tech icon
        let categoryName = detection.category || 'unknown';
        switch(categoryName) {
          case 'education': categoryIcon = '🎓'; break;
          case 'ecommerce': categoryIcon = '🛒'; break;
          case 'social': categoryIcon = '👥'; break;
          case 'financial': categoryIcon = '🏦'; break;
          case 'gaming': categoryIcon = '🎮'; break;
          case 'streaming': categoryIcon = '🎬'; break;
          case 'technology': categoryIcon = '💻'; break;
          case 'government': categoryIcon = '🏛️'; break;
          case 'healthcare': categoryIcon = '🏥'; break;
          case 'news': categoryIcon = '📰'; break;
        }
        categoryName = categoryName.charAt(0).toUpperCase() + categoryName.slice(1);
        
        // Check for suspicious TLD
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
          '.date', '.bid', '.stream', '.download', '.loan'];
        
        let tldHTML = '';
        try {
          const domain = new URL(detection.url).hostname;
          const hasSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));
          
          if (hasSuspiciousTLD && document.getElementById('monitor-suspicious-tlds').checked) {
            tldHTML = `
              <span class="suspicious-tld" style="margin-left: 8px;">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                  <line x1="12" y1="9" x2="12" y2="13"></line>
                  <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                Suspicious TLD
              </span>
            `;
          }
        } catch (e) {
          console.error("Invalid URL in detection history:", e);
        }
        
        // Add phishing count information
        let phishingCountHTML = '';
        if (detection.phishingCount && detection.phishingCount > 1) {
          phishingCountHTML = `
            <div style="margin-top: 6px; font-size: 12px; color: var(--danger-color);">
              ⚠️ Multiple detections from this domain (${detection.phishingCount})
            </div>
          `;
        }
        
        detectionDiv.innerHTML = `
          <div class="detection-url">${detection.url}</div>
          <div class="detection-time">${formattedDate}</div>
          <div class="detection-result ${detection.classification.toLowerCase()}">${detection.classification}</div>
          <div>Confidence: ${(detection.confidence * 100).toFixed(2)}%</div>
          <div style="margin-top: 8px;">
            <span class="domain-category">
              <span class="category-icon">${categoryIcon}</span>${categoryName}
            </span>
            ${tldHTML}
          </div>
          ${phishingCountHTML}
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
        sensitivityLevel: 3,
        monitorSuspiciousTlds: true
      };
      
      document.getElementById('real-time-protection').checked = settings.realTimeProtection;
      document.getElementById('show-warnings').checked = settings.showWarnings;
      document.getElementById('check-domain-age').checked = settings.checkDomainAge;
      document.getElementById('advanced-analysis').checked = settings.advancedAnalysis;
      
      // Handle sensitivity slider
      const sensitivitySlider = document.getElementById('sensitivity-level');
      if (sensitivitySlider) {
        sensitivitySlider.value = settings.sensitivityLevel;
      }
      
      // Set monitor suspicious TLDs checkbox
      document.getElementById('monitor-suspicious-tlds').checked = 
        settings.monitorSuspiciousTlds !== undefined ? settings.monitorSuspiciousTlds : true;
    });
  }
  
  // Save settings to storage
  function saveSettings() {
    const settings = {
      realTimeProtection: document.getElementById('real-time-protection').checked,
      showWarnings: document.getElementById('show-warnings').checked,
      checkDomainAge: document.getElementById('check-domain-age').checked,
      advancedAnalysis: document.getElementById('advanced-analysis').checked,
      sensitivityLevel: parseInt(document.getElementById('sensitivity-level').value),
      monitorSuspiciousTlds: document.getElementById('monitor-suspicious-tlds').checked
    };
    
    chrome.storage.local.set({ settings });
    
    // Send updated settings to background script
    chrome.runtime.sendMessage({ action: "updateSettings", settings });
  }
  
  // Load statistics
  function loadStatistics() {
    chrome.runtime.sendMessage({ action: "getAllPhishingStatistics" }, function(statistics) {
      console.log("Received statistics:", statistics);
      
      if (!statistics || !statistics.totalPhishingAttempts) {
        console.log("No statistics received or empty statistics");
        statistics = {
          domainCounts: {},
          categoryCounts: {},
          categoryPercentages: {},
          totalPhishingAttempts: 0,
          mostTargetedCategory: ['unknown', 0]
        };
      }
      
      // Update total count
      document.getElementById('total-count').textContent = statistics.totalPhishingAttempts || 0;
      
      // Update most targeted category
      const mostTargetedCategory = statistics.mostTargetedCategory ? 
        (statistics.mostTargetedCategory[0].charAt(0).toUpperCase() + 
         statistics.mostTargetedCategory[0].slice(1)) : 'None yet';
      
      document.getElementById('most-targeted-category').textContent = mostTargetedCategory;
      
      // Update category statistics
      const categoryStatsDiv = document.getElementById('category-statistics');
      categoryStatsDiv.innerHTML = '';
      
      // Get sorted categories by count
      const categories = Object.keys(statistics.categoryCounts || {})
        .filter(category => statistics.categoryCounts[category] > 0)
        .sort((a, b) => statistics.categoryCounts[b] - statistics.categoryCounts[a]);
      
      if (categories.length > 0) {
        categories.slice(0, 4).forEach(category => {
          const count = statistics.categoryCounts[category];
          const percentage = statistics.totalPhishingAttempts ? 
            ((count / statistics.totalPhishingAttempts) * 100).toFixed(1) + '%' : '0%';
          
          const categoryName = category.charAt(0).toUpperCase() + category.slice(1);
          let categoryIcon = '💻'; // Default tech icon
          
          switch(category) {
            case 'education': categoryIcon = '🎓'; break;
            case 'ecommerce': categoryIcon = '🛒'; break;
            case 'social': categoryIcon = '👥'; break;
            case 'financial': categoryIcon = '🏦'; break;
            case 'gaming': categoryIcon = '🎮'; break;
            case 'streaming': categoryIcon = '🎬'; break;
            case 'technology': categoryIcon = '💻'; break;
            case 'government': categoryIcon = '🏛️'; break;
            case 'healthcare': categoryIcon = '🏥'; break;
            case 'news': categoryIcon = '📰'; break;
          }
          
          const div = document.createElement('div');
          div.className = 'category-stat-item';
          div.innerHTML = `
            <div class="category-stat-name">
              <span class="category-icon">${categoryIcon}</span>${categoryName}
            </div>
            <div class="category-stat-value">${count}</div>
            <div class="category-stat-percentage">${percentage}</div>
          `;
          
          categoryStatsDiv.appendChild(div);
        });
      } else {
        categoryStatsDiv.innerHTML = '<div style="padding: 8px;">No data available yet</div>';
      }
      
      // Update domain statistics
      const domainStatsDiv = document.getElementById('domain-statistics');
      domainStatsDiv.innerHTML = '';
      
      // Get domains with phishing counts
      const domains = Object.keys(statistics.domainCounts || {})
        .filter(domain => statistics.domainCounts[domain] > 0)
        .sort((a, b) => statistics.domainCounts[b] - statistics.domainCounts[a]);
      
      if (domains.length > 0) {
        domains.slice(0, 4).forEach(domain => {
          const count = statistics.domainCounts[domain];
          const percentage = statistics.totalPhishingAttempts ? 
            ((count / statistics.totalPhishingAttempts) * 100).toFixed(1) + '%' : '0%';
          
          const div = document.createElement('div');
          div.className = 'category-stat-item';
          div.innerHTML = `
            <div class="category-stat-name" style="word-break: break-all;">
              ${domain}
            </div>
            <div class="category-stat-value">${count}</div>
            <div class="category-stat-percentage">${percentage}</div>
          `;
          
          domainStatsDiv.appendChild(div);
        });
      } else {
        domainStatsDiv.innerHTML = '<div style="padding: 8px;">No data available yet</div>';
      }
    });
  }
  
  // Load current page URL on popup open
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith('http')) {
      document.getElementById('url-input').value = tabs[0].url;
    }
  });
});
