// Content script for Phishing URL Detector

// Create and append warning overlay to the page
function createWarningOverlay(result) {
    // Remove any existing overlay first
    removeWarningOverlay();
    
    // Create overlay container
    const overlay = document.createElement('div');
    overlay.id = 'phishing-detector-warning';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(234, 67, 53, 0.9);
      z-index: 2147483647;
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    `;
    
    // Create warning content
    const content = document.createElement('div');
    content.style.cssText = `
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
      width: 90%;
      max-width: 600px;
      padding: 24px;
      text-align: center;
    `;
    
    // Warning icon and title
    content.innerHTML = `
      <div style="color: #EA4335; font-size: 48px; margin-bottom: 16px;">⚠️</div>
      <h1 style="color: #EA4335; font-size: 24px; margin-bottom: 16px;">Warning: Potential Phishing Detected</h1>
      <p style="color: #202124; font-size: 16px; margin-bottom: 24px;">
        This website has been detected as a potential phishing site with 
        <strong>${(result.confidence * 100).toFixed(1)}%</strong> confidence.
      </p>
    `;
    
    // Add domain information if available
    if (result.urlInfo && result.urlInfo.domain) {
      const domainInfo = document.createElement('div');
      domainInfo.style.cssText = `
        background-color: #F8F9FA;
        padding: 16px;
        border-radius: 8px;
        margin-bottom: 24px;
        text-align: left;
      `;
      
      // Add domain age if available
      let domainAgeText = '';
      if (result.domainAge) {
        domainAgeText = `
          <p style="margin: 8px 0;">
            Domain Age: <strong>${result.domainAge.ageInDays} days</strong>
            (Registered: ${result.domainAge.registrationDate})
          </p>
        `;
      }
      
      // Add phishing count if available
      let phishingCountText = '';
      if (result.phishingCount && result.phishingCount > 0) {
        phishingCountText = `
          <p style="margin: 8px 0; color: #EA4335;">
            <strong>This domain has been detected in ${result.phishingCount} phishing attempts.</strong>
          </p>
        `;
      }
      
      domainInfo.innerHTML = `
        <p style="margin: 8px 0;">Domain: <strong>${result.urlInfo.domain}</strong></p>
        ${domainAgeText}
        ${phishingCountText}
      `;
      
      content.appendChild(domainInfo);
    }
    
    // Add action buttons
    const buttons = document.createElement('div');
    buttons.style.cssText = `
      display: flex;
      justify-content: center;
      gap: 16px;
    `;
    
    // Back to safety button
    const backButton = document.createElement('button');
    backButton.innerText = 'Back to Safety';
    backButton.style.cssText = `
      background-color: #4285F4;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 4px;
      font-weight: 500;
      cursor: pointer;
    `;
    backButton.addEventListener('click', () => {
      history.back();
    });
    
    // Proceed anyway button
    const proceedButton = document.createElement('button');
    proceedButton.innerText = 'Proceed Anyway';
    proceedButton.style.cssText = `
      background-color: transparent;
      color: #5F6368;
      border: 1px solid #DADCE0;
      padding: 12px 24px;
      border-radius: 4px;
      font-weight: 500;
      cursor: pointer;
    `;
    proceedButton.addEventListener('click', () => {
      removeWarningOverlay();
    });
    
    buttons.appendChild(backButton);
    buttons.appendChild(proceedButton);
    content.appendChild(buttons);
    overlay.appendChild(content);
    document.body.appendChild(overlay);
  }
  
  // Remove warning overlay from page
  function removeWarningOverlay() {
    const existingOverlay = document.getElementById('phishing-detector-warning');
    if (existingOverlay) {
      existingOverlay.remove();
    }
  }
  
  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showWarning') {
      createWarningOverlay(message.data);
      sendResponse({ success: true });
    }
  });
  
  // Ensure the extension works correctly when navigating to new pages
  // This is necessary because content scripts might be loaded after
  // the DOM is already rendered
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeContentScript);
  } else {
    initializeContentScript();
  }
  
  function initializeContentScript() {
    // This ensures that any message handlers are set up before messages arrive
    console.log('Phishing URL Detector content script initialized');
  }
