# 🛡️ Phishing URL Detector Extension

![Version](https://img.shields.io/badge/version-1.0-green.svg)

## 📋 Overview

Phishing URL Detector is a powerful Chrome extension designed to protect users from phishing attacks by analyzing URLs in real-time. Using advanced heuristic algorithms and feature extraction techniques, the extension evaluates URLs to identify potential phishing attempts before users interact with malicious websites.


## ✨ Features

- 🔍 **Real-time URL Analysis**: Automatically scans websites as you browse
- ⚠️ **Warning Overlay**: Displays alerts when potentially dangerous websites are detected
- 📊 **Detailed Reports**: Provides comprehensive analysis with confidence scores and risk factors
- 🕰️ **Domain Age Verification**: Checks how recently domains were registered (new domains are often used for phishing)
- 📜 **Detection History**: Maintains a log of all detected phishing attempts
- 🔧 **Customizable Settings**: Adjust sensitivity levels and protection features to your preferences
- 🧠 **Advanced Pattern Recognition**: Identifies suspicious patterns in URLs that may indicate phishing attempts
- 🔄 **Regular Updates**: Algorithm is designed to detect emerging phishing techniques

## 🔧 Installation

### From Chrome Web Store (Coming Soon)
1. Visit the Chrome Web Store
2. Search for "Phishing URL Detector"
3. Click "Add to Chrome"

### Manual Installation
1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked" and select the extension directory
5. The extension is now installed and active!

## 🚀 How to Use

### Analyze Current Page
1. Click the Phishing URL Detector icon in your browser toolbar
2. Select "Analyze Current Page" to scan the website you're currently visiting

### Analyze a Specific URL
1. Click the extension icon
2. Enter a URL in the text field
3. Click "Analyze URL" to evaluate the security of the specified website

### Review Detection History
1. Open the extension popup
2. Select the "History" tab to view past detections
3. Review details of previously analyzed URLs

### Customize Settings
1. Access the "Settings" tab in the extension popup
2. Adjust protection features according to your preferences:
   - Toggle real-time protection
   - Adjust sensitivity level
   - Enable/disable warning overlays
   - Configure domain age checks

## 🧩 How It Works

The Phishing URL Detector employs multiple analysis techniques to identify potential threats:

1. **URL Feature Extraction**: Analyzes domain length, path structure, special characters, and other URL components
2. **Pattern Recognition**: Identifies suspicious patterns commonly found in phishing URLs
3. **Domain Age Verification**: Checks how recently domains were registered
4. **Keyword Analysis**: Scans for suspicious terms frequently used in phishing attempts
5. **Subdomain Analysis**: Evaluates the complexity and structure of subdomains

Based on these factors, the extension calculates a risk score and classifies URLs as either legitimate or potentially dangerous.

## 🛠️ Technical Details

The extension is built using:
- JavaScript (ES6+)
- Chrome Extension Manifest V3
- Local storage for settings and history management
- Domain age verification API integration (simulated in current version)

Key components:
- `background.js`: Core analysis engine and background service
- `popup.js`: User interface controller
- `popup.html`: Extension popup interface
- `manifest.json`: Extension configuration and permissions

## 📈 Future Improvements

- [ ] Machine learning model integration for improved detection
- [ ] Safe browsing API integration
- [ ] Customizable whitelist for trusted domains
- [ ] Email link analysis for detecting phishing attempts in messages
- [ ] Browser fingerprint detection for advanced threat identification
- [ ] Performance optimizations for faster analysis
- [ ] Additional language support

## 👥 Contributing

Contributions are welcome! If you'd like to improve the Phishing URL Detector:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🖥️ Demo
![image](https://github.com/user-attachments/assets/0a2d7982-1c88-4072-9d0c-52a3f84bd054)
![image](https://github.com/user-attachments/assets/327f58c2-fea4-42d1-a271-c3991fecb4af)
![image](https://github.com/user-attachments/assets/41d50f4f-8b11-4690-a3b5-08c22fe3e4b7)
![image](https://github.com/user-attachments/assets/4a91ffee-bfc7-4bfa-8448-660727e35980)



## 📞 Contact

Feel free to reach out if you have questions, suggestions, or would like to contribute:

- GitHub: Open an issue in this repository
- Email: aryankaminwar@gmail.com 

## 🔒 Privacy

The Phishing URL Detector extension:
- Does not collect or transmit user browsing data
- Performs all analysis locally on your device
- Does not share URLs or browsing history with any third parties
- Requires only the necessary permissions to function properly

## 🙏 Acknowledgments

- Icon designed by Aryan Kaminwar
- Special thanks to all contributors
- Inspired by the need for better phishing protection in modern browsers
