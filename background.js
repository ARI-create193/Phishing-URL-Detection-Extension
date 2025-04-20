const suspiciousKeywords = [
  'login', 'secure', 'account', 'verify', 'update', 'bank',
  'paypal', 'amazon', 'apple', 'microsoft', 'netflix',
  'password', 'urgent', 'suspended', 'limited',
  'validation', 'recovery', 'security', 'confirm'
];

const suspiciousPatterns = [
  /\d+\.[a-z]+\.[a-z]+/,
  /[0-9]{3,}\.[a-z]+/,
  /[a-z]+-[a-z]+\.[a-z]+/
];

// Domain category keywords
const domainCategories = {
  education: ['university', 'edu', 'college', 'academic', 'school', 'learning', 'blackboard', 'canvas', 'moodle', 'scholar', 'edu.co', 'academy', 'institute', 'seminar', 'course', 'education'],
  ecommerce: ['ebay', 'amazon', 'shop', 'store', 'buy', 'product', 'mall', 'market', 'retail', 'sale', 'cart', 'checkout', 'order', 'shopping', 'alibaba', 'walmart', 'target', 'merchant'],
  social: ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'social', 'friend', 'connect', 'network', 'chat', 'messenger', 'whatsapp', 'snapchat', 'pinterest', 'reddit', 'telegram', 'discord'],
  financial: ['bank', 'paypal', 'crypto', 'wallet', 'payment', 'finance', 'credit', 'debit', 'loan', 'money', 'investment', 'stock', 'bitcoin', 'blockchain', 'card', 'visa', 'mastercard', 'exchange'],
  gaming: ['game', 'steam', 'epic', 'origin', 'battle', 'league', 'fortnite', 'minecraft', 'xbox', 'playstation', 'nintendo', 'esports', 'blizzard', 'riot', 'valve', 'gaming'],
  streaming: ['netflix', 'amazon prime', 'hulu', 'disney', 'youtube', 'twitch', 'vimeo', 'paramount', 'stream', 'watch', 'video', 'movie', 'tv', 'series', 'episode', 'crunchyroll'],
  technology: ['microsoft', 'apple', 'google', 'icloud', 'dropbox', 'drive', 'office', 'adobe', 'software', 'tech', 'support', 'update', 'download', 'windows', 'macos', 'android', 'ios'],
  government: ['gov', 'government', 'federal', 'state', 'city', 'municipality', 'agency', 'department', 'public', 'passport', 'tax', 'service', 'military', 'court', 'justice', 'official'],
  healthcare: ['health', 'medical', 'doctor', 'hospital', 'clinic', 'pharmacy', 'medicine', 'patient', 'healthcare', 'insurance', 'treatment', 'diagnosis', 'nursing', 'covid', 'vaccine'],
  news: ['news', 'media', 'article', 'journal', 'magazine', 'press', 'daily', 'times', 'post', 'herald', 'tribune', 'cnn', 'bbc', 'reuters', 'associated press', 'blog']
};

// Default settings
let settings = {
  realTimeProtection: true,
  showWarnings: true,
  checkDomainAge: true,
  advancedAnalysis: true,
  sensitivityLevel: 3
};

// Maintain a dictionary of domain-based phishing counts
let domainPhishingCounts = {};

// NEW: Track phishing counts by category
let categoryPhishingCounts = {
  education: 0,
  ecommerce: 0,
  social: 0,
  financial: 0,
  gaming: 0,
  streaming: 0,
  technology: 0,
  government: 0,
  healthcare: 0,
  news: 0,
  unknown: 0
};

// Load settings, domain counts, and category counts on extension startup
chrome.storage.local.get(['settings', 'domainPhishingCounts', 'categoryPhishingCounts'], (data) => {
  if (data.settings) {
    settings = data.settings;
  }
  
  if (data.domainPhishingCounts) {
    domainPhishingCounts = data.domainPhishingCounts;
  }
  
  // NEW: Load category phishing counts
  if (data.categoryPhishingCounts) {
    categoryPhishingCounts = data.categoryPhishingCounts;
  }
});

// Function to extract domain from URL
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    // Handle malformed URLs
    const domainRegex = /^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/i;
    const matches = url.match(domainRegex);
    return matches ? matches[1] : url;
  }
}

// Function to determine domain category
function determineDomainCategory(url) {
  const domain = extractDomain(url).toLowerCase();
  const urlLower = url.toLowerCase();
  
  let matchedCategories = [];
  
  // Check each category for matches
  for (const [category, keywords] of Object.entries(domainCategories)) {
    const hasMatch = keywords.some(keyword => {
      return domain.includes(keyword) || urlLower.includes(keyword);
    });
    
    if (hasMatch) {
      matchedCategories.push(category);
    }
  }
  
  // Return the first match or 'unknown' if no matches
  return matchedCategories.length > 0 ? matchedCategories[0] : 'unknown';
}

// Preprocess URL to extract features
function preprocessUrl(url) {
  try {
    // Ensure URL has a protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'http://' + url;
    }
    
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
    const query = urlObj.search;
    
    // Calculate features
    const domainLength = domain.length;
    const pathLength = path.length;
    const hasSuspiciousWords = suspiciousKeywords.some(word => url.toLowerCase().includes(word));
    const hasIpAddress = /\d+\.\d+\.\d+\.\d+/.test(domain);
    const numDots = domain.split('.').length - 1;
    const numHyphens = domain.split('-').length - 1;
    const numAtSymbols = domain.split('@').length - 1;
    const numEquals = query.split('=').length - 1;
    const numDigits = (domain.match(/\d/g) || []).length;
    const subdomainLevels = domain.split('.').length - 1;
    const category = determineDomainCategory(url);
    
    return {
      url,
      domain,
      category,
      domainLength,
      pathLength,
      hasSuspiciousWords,
      hasIpAddress,
      numDots,
      numHyphens,
      numAtSymbols,
      numEquals,
      numDigits,
      subdomainLevels
    };
  } catch (e) {
    console.error("Error preprocessing URL:", e);
    return {
      url,
      domain: extractDomain(url),
      category: 'unknown',
      domainLength: 0,
      pathLength: 0,
      hasSuspiciousWords: false,
      hasIpAddress: false,
      numDots: 0,
      numHyphens: 0,
      numAtSymbols: 0,
      numEquals: 0,
      numDigits: 0,
      subdomainLevels: 0
    };
  }
}

// Check domain age
async function checkDomainAge(domain) {
  // In a real implementation, this would call a WHOIS API service
  // For this demo, we simulate a domain age check
  return new Promise((resolve) => {
    setTimeout(() => {
      // Generate a random age between 1 day and 10 years
      // With higher probability for older domains
      let ageInDays;
      const rand = Math.random();
      
      if (rand < 0.1) {
        // 10% chance of a very new domain (1-30 days)
        ageInDays = Math.floor(Math.random() * 30) + 1;
      } else if (rand < 0.2) {
        // 10% chance of a new domain (30-90 days)
        ageInDays = Math.floor(Math.random() * 60) + 30;
      } else if (rand < 0.4) {
        // 20% chance of a relatively new domain (3-12 months)
        ageInDays = Math.floor(Math.random() * 270) + 90;
      } else {
        // 60% chance of an established domain (1-10 years)
        ageInDays = Math.floor(Math.random() * 3285) + 365;
      }
      
      const registrationDate = new Date(Date.now() - ageInDays * 24 * 60 * 60 * 1000);
      
      resolve({
        domain: domain,
        ageInDays: ageInDays,
        registrationDate: registrationDate.toISOString().split('T')[0],
        isSuspicious: ageInDays < 30 // Domains less than 30 days old are flagged as suspicious
      });
    }, 200);
  });
}

// Analyze URL features to determine phishing probability
function analyzeUrlFeatures(urlInfo) {
  let score = 0.0;
  const sensitivityMultiplier = settings.sensitivityLevel / 3; // Normalize sensitivity (1-5 scale)
  
  // Check for suspicious patterns
  if (urlInfo.hasSuspiciousWords) {
    score += 0.5 * sensitivityMultiplier;
  }
  
  if (urlInfo.domainLength > 30) {
    score += 0.3 * sensitivityMultiplier;
  }
  
  if (urlInfo.numHyphens > 2) {
    score += 0.3 * sensitivityMultiplier;
  }
  
  // Check against suspicious patterns
  const url = urlInfo.url.toLowerCase();
  if (suspiciousPatterns.some(pattern => pattern.test(url))) {
    score += 0.25 * sensitivityMultiplier;
  }
  
  if (urlInfo.hasIpAddress) {
    score += 0.3 * sensitivityMultiplier;
  }
  
  if (urlInfo.numDots > 3) {
    score += 0.1 * Math.min(urlInfo.numDots, 5) * sensitivityMultiplier;
  }
  
  if (urlInfo.numAtSymbols > 0) {
    score += 0.2 * sensitivityMultiplier;
  }
  
  if (urlInfo.numEquals > 3) {
    score += 0.1 * sensitivityMultiplier;
  }
  
  if (urlInfo.numDigits > 3) {
    score += 0.1 * Math.min(urlInfo.numDigits / 3, 3) * sensitivityMultiplier;
  }
  
  if (urlInfo.subdomainLevels > 2) {
    score += 0.2 * Math.min(urlInfo.subdomainLevels, 5) * sensitivityMultiplier;
  }
  
  if (urlInfo.pathLength > 50) {
    score += 0.15 * sensitivityMultiplier;
  }
  
  // Check for lookalike domains
  if (/amaz0n|paypa1|micr0soft|netf1ix|g00gle|faceb00k|inst[a@]gr[a@]m/.test(url)) {
    score += 0.5 * sensitivityMultiplier;
  }
  
  // Check for unusual characters
  if (/[\[\]\(\)\{\}]/.test(url)) {
    score += 0.3 * sensitivityMultiplier;
  }
  
  // Domain age factor
  if (urlInfo.domainAge && urlInfo.domainAge.isSuspicious) {
    score += 0.35 * sensitivityMultiplier;
  }
  
  // Cap score at 0.95
  score = Math.min(score, 0.95);
  
  // Determine if phishing based on score
  // Adjust threshold based on sensitivity
  const threshold = 0.3 - ((settings.sensitivityLevel - 3) * 0.05);
  const isPhishing = score > threshold;
  const confidence = isPhishing ? score : 1 - score;
  
  return {
    classification: isPhishing ? "Phishing" : "Legitimate",
    confidence: confidence,
    score: score
  };
}

// Generate explanation for the prediction
function explainPrediction(url, result, urlInfo) {
  let explanation = `The URL '${url}' is classified as ${result.classification} with ${(result.confidence * 100).toFixed(2)}% confidence.\n\n`;
  
  explanation += "Extracted Features:\n";
  explanation += `- Domain: ${urlInfo.domain}\n`;
  explanation += `- Domain Category: ${urlInfo.category.charAt(0).toUpperCase() + urlInfo.category.slice(1)}\n`;
  explanation += `- Domain Length: ${urlInfo.domainLength} characters\n`;
  explanation += `- Path Length: ${urlInfo.pathLength} characters\n`;
  explanation += `- Number of Dots: ${urlInfo.numDots}\n`;
  explanation += `- Number of Hyphens: ${urlInfo.numHyphens}\n`;
  
  // Add domain phishing count if available
  if (domainPhishingCounts[urlInfo.domain]) {
    explanation += `- Phishing URLs detected from this domain: ${domainPhishingCounts[urlInfo.domain]}\n`;
  }
  
  // NEW: Add category phishing count
  if (categoryPhishingCounts[urlInfo.category]) {
    explanation += `- Phishing URLs detected in ${urlInfo.category} category: ${categoryPhishingCounts[urlInfo.category]}\n`;
  }
  
  // Add risk factors
  const riskFactors = [];
  if (urlInfo.hasSuspiciousWords) {
    riskFactors.push("Contains suspicious words (login, secure, account, etc.)");
  }
  if (urlInfo.hasIpAddress) {
    riskFactors.push("Uses IP address instead of domain name");
  }
  if (urlInfo.domainLength > 30) {
    riskFactors.push("Unusually long domain name");
  }
  if (urlInfo.numDots > 3) {
    riskFactors.push(`Contains an unusual number of dots (${urlInfo.numDots})`);
  }
  if (urlInfo.numHyphens > 2) {
    riskFactors.push(`Contains multiple hyphens (${urlInfo.numHyphens})`);
  }
  if (urlInfo.numAtSymbols > 0) {
    riskFactors.push("Contains @ symbol in URL (highly suspicious)");
  }
  if (urlInfo.subdomainLevels > 2) {
    riskFactors.push(`Contains many subdomain levels (${urlInfo.subdomainLevels})`);
  }
  if (urlInfo.domainAge && urlInfo.domainAge.isSuspicious) {
    riskFactors.push(`Recently registered domain (${urlInfo.domainAge.ageInDays} days old)`);
  }
  if (domainPhishingCounts[urlInfo.domain] && domainPhishingCounts[urlInfo.domain] > 1) {
    riskFactors.push(`Multiple phishing attempts detected from this domain (${domainPhishingCounts[urlInfo.domain]} total)`);
  }
  
  if (riskFactors.length > 0) {
    explanation += "\nRisk Factors Detected:\n";
    riskFactors.forEach(factor => {
      explanation += `- ${factor}\n`;
    });
  }
  
  return explanation;
}

// Function to update domain phishing count
function updateDomainPhishingCount(domain, category) {
  if (!domainPhishingCounts[domain]) {
    domainPhishingCounts[domain] = 1;
  } else {
    domainPhishingCounts[domain]++;
  }
  
  // NEW: Update category phishing count
  if (category && categoryPhishingCounts.hasOwnProperty(category)) {
    categoryPhishingCounts[category]++;
  } else {
    categoryPhishingCounts.unknown++;
  }
  
  // Save updated counts to storage
  chrome.storage.local.set({ 
    domainPhishingCounts,
    categoryPhishingCounts  // NEW: Save category counts
  });
}

// Analyze a URL and return results
async function analyzeUrl(url, checkDomainAgeOption = true) {
  const urlInfo = preprocessUrl(url);
  
  // Check domain age if enabled
  if (settings.checkDomainAge && checkDomainAgeOption) {
    try {
      urlInfo.domainAge = await checkDomainAge(urlInfo.domain);
    } catch (error) {
      console.error("Error checking domain age:", error);
    }
  }
  
  const result = analyzeUrlFeatures(urlInfo);
  
  // Add domain phishing count to URL info if available
  if (domainPhishingCounts[urlInfo.domain]) {
    urlInfo.phishingCount = domainPhishingCounts[urlInfo.domain];
  } else {
    urlInfo.phishingCount = 0;
  }
  
  // NEW: Add category phishing count
  if (categoryPhishingCounts[urlInfo.category]) {
    urlInfo.categoryPhishingCount = categoryPhishingCounts[urlInfo.category];
  } else {
    urlInfo.categoryPhishingCount = 0;
  }
  
  const explanation = explainPrediction(url, result, urlInfo);
  
  return {
    url,
    classification: result.classification,
    confidence: result.confidence,
    score: result.score,
    explanation: explanation,
    urlInfo: urlInfo,
    domainAge: urlInfo.domainAge,
    phishingCount: urlInfo.phishingCount,
    categoryPhishingCount: urlInfo.categoryPhishingCount,  // NEW: Include category count
    category: urlInfo.category  // NEW: Include category
  };
}

// Listen for URL changes
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (!settings.realTimeProtection) return;
  
  const url = details.url;
  
  // Skip chrome:// URLs and other browser URLs
  if (!url.startsWith('http')) return;
  
  const result = await analyzeUrl(url);
  
  // If the URL is likely phishing, show a warning
  if (result.classification === "Phishing" && result.confidence > 0.5 && settings.showWarnings) {
    chrome.tabs.sendMessage(details.tabId, {
      action: "showWarning",
      data: result
    });
    
    // Update domain and category phishing counts
    if (result.urlInfo && result.urlInfo.domain) {
      updateDomainPhishingCount(result.urlInfo.domain, result.urlInfo.category);
    }
    
    // Store this detection
    chrome.storage.local.get('detections', (data) => {
      const detections = data.detections || [];
      detections.push({
        url: url,
        timestamp: new Date().toISOString(),
        classification: result.classification,
        confidence: result.confidence,
        domainAge: result.domainAge,
        category: result.urlInfo.category,
        domain: result.urlInfo.domain,
        phishingCount: domainPhishingCounts[result.urlInfo.domain] || 1,
        categoryPhishingCount: categoryPhishingCounts[result.urlInfo.category] || 1  // NEW: Include category count
      });
      
      // Limit stored detections to most recent 100
      if (detections.length > 100) {
        detections.splice(100);
      }
      
      chrome.storage.local.set({ detections });
    });
  }
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyzeUrl") {
    analyzeUrl(message.url, message.checkDomainAge)
      .then(result => {
        // If URL is classified as phishing, update the count
        if (result.classification === "Phishing" && result.confidence > 0.5) {
          if (result.urlInfo && result.urlInfo.domain) {
            updateDomainPhishingCount(result.urlInfo.domain, result.urlInfo.category);
            // Update the result with the new counts
            result.phishingCount = domainPhishingCounts[result.urlInfo.domain];
            result.categoryPhishingCount = categoryPhishingCounts[result.urlInfo.category];
          }
        }
        sendResponse(result);
      });
    return true; // Required for async response
  } else if (message.action === "getDetections") {
    chrome.storage.local.get('detections', (data) => {
      const detections = data.detections || [];
      
      // Add domain and category phishing counts to each detection
      detections.forEach(detection => {
        if (detection.domain) {
          detection.phishingCount = domainPhishingCounts[detection.domain] || 0;
        }
        if (detection.category) {
          detection.categoryPhishingCount = categoryPhishingCounts[detection.category] || 0;
        }
      });
      
      sendResponse(detections);
    });
    return true; // Required for async response
  } else if (message.action === "clearDetections") {
    chrome.storage.local.set({ detections: [] });
    // Optionally clear domain phishing counts
    // domainPhishingCounts = {};
    // chrome.storage.local.set({ domainPhishingCounts: {} });
    sendResponse({ success: true });
  } else if (message.action === "updateSettings") {
    settings = message.settings;
    chrome.storage.local.set({ settings });
    sendResponse({ success: true });
  } else if (message.action === "getDomainPhishingCounts") {
    sendResponse(domainPhishingCounts);
  } 
  // NEW: Add handler for getting category statistics
  else if (message.action === "getCategoryPhishingCounts") {
    sendResponse(categoryPhishingCounts);
  }
  // NEW: Add handler for getting all statistics
  else if (message.action === "getAllPhishingStatistics") {
    // Get total across all categories
    const totalPhishingAttempts = Object.values(categoryPhishingCounts).reduce((a, b) => a + b, 0);
    
    // Calculate percentages for each category
    const categoryPercentages = {};
    for (const [category, count] of Object.entries(categoryPhishingCounts)) {
      categoryPercentages[category] = totalPhishingAttempts > 0 ? 
        ((count / totalPhishingAttempts) * 100).toFixed(1) + '%' : '0%';
    }
    
    sendResponse({
      domainCounts: domainPhishingCounts,
      categoryCounts: categoryPhishingCounts,
      categoryPercentages: categoryPercentages,
      totalPhishingAttempts: totalPhishingAttempts,
      mostTargetedCategory: Object.entries(categoryPhishingCounts)
        .sort((a, b) => b[1] - a[1])[0]
    });
  }
});

// Additional suspicious TLDs to monitor
const suspiciousTLDs = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
  '.date', '.bid', '.stream', '.download', '.loan'
];

// Function to check for suspicious TLD
function hasSuspiciousTLD(domain) {
  return suspiciousTLDs.some(tld => domain.endsWith(tld));
}

// Initialize settings, domainPhishingCounts and categoryPhishingCounts when extension is installed
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['settings', 'domainPhishingCounts', 'categoryPhishingCounts'], (data) => {
    if (!data.settings) {
      chrome.storage.local.set({ 
        settings: {
          realTimeProtection: true,
          showWarnings: true,
          checkDomainAge: true,
          advancedAnalysis: true,
          sensitivityLevel: 3
        }
      });
    }
    
    if (!data.domainPhishingCounts) {
      chrome.storage.local.set({ domainPhishingCounts: {} });
    }
    
    // NEW: Initialize category counts if not present
    if (!data.categoryPhishingCounts) {
      chrome.storage.local.set({ 
        categoryPhishingCounts: {
          education: 0,
          ecommerce: 0,
          social: 0,
          financial: 0,
          gaming: 0,
          streaming: 0,
          technology: 0,
          government: 0,
          healthcare: 0,
          news: 0,
          unknown: 0
        }
      });
    }
  });
});
