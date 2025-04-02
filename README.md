# 🛡️ Phishing URL Detection

## 🔍 Overview

Phishing attacks are a significant cybersecurity threat, targeting users by tricking them into providing sensitive information such as usernames, passwords, and financial details. This project focuses on developing an AI-powered phishing URL detection system using machine learning and natural language processing techniques.

The system utilizes a combination of heuristic-based features, WHOIS domain data, and transformer-based deep learning models to classify URLs as either phishing or legitimate. The project also features an interactive web-based interface using Gradio for real-time phishing detection.

## 🚀 Features

- **Advanced Machine Learning Techniques**: Utilizes NLP-based transformers for analyzing URL structures.
- **Feature Extraction**: Extracts lexical, host-based, and content-based features from URLs.
- **WHOIS Data Integration**: Retrieves domain registration details to check for suspicious activity.
- **Real-Time Detection**: Provides instant results through an easy-to-use web interface.
- **Visualization Tools**: Includes plots and metrics to analyze model performance.
- **Customizable Model**: Supports fine-tuning of parameters and model retraining with new data.

## ⚙️ Installation

To set up the project on your local machine, follow these steps:

### 📌 Prerequisites

Ensure you have Python installed (recommended version 3.8 or above). Install the required dependencies using:

```bash
pip install gradio python-whois transformers torch numpy pandas matplotlib scikit-learn joblib tqdm requests
```

### 📥 Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-url-detection.git
cd phishing-url-detection
```

### ▶️ Running the Application

To start the phishing URL detection system, run:

```bash
python main.py
```

Or, if using a Jupyter Notebook:

1. Open `phishing_detection.ipynb` in Jupyter Notebook.
2. Execute the cells sequentially.

📝 Demo
![image](https://github.com/user-attachments/assets/76a3fced-a21c-420b-9d8c-a50394732490)

![image](https://github.com/user-attachments/assets/1356095a-aa35-4781-9d81-798e30e4a929)



## 🛠️ How It Works

The detection model follows a multi-step approach:

1. **Feature Extraction**: The input URL is processed to extract various characteristics such as:
   - URL Length, Special Characters, Subdomains
   - Domain Age, Registrar Information (from WHOIS Lookup)
   - Presence of IP addresses in the URL
   - HTTPS vs HTTP usage
2. **Text Analysis**: Using TF-IDF and NLP techniques, the text content of URLs is analyzed.
3. **Model Prediction**: The extracted features are passed to a machine learning classifier (e.g., Random Forest, Logistic Regression, or Transformer-based models) for classification.
4. **Result Display**: The model outputs whether the URL is phishing or legitimate, along with confidence scores.

## 📊 Example Usage

1. Open the Gradio web interface.
2. Enter a suspicious URL in the input field.
3. Click the "Check URL" button.
4. The model will analyze and display the results.

## 📂 Dataset

The model is trained on a combination of:

- Open-source phishing datasets (e.g., PhishTank, OpenPhish)
- Legitimate URL datasets from Alexa and Common Crawl
- Custom labeled data collected through web scraping

## 📁 File Structure

```
📂 phishing-url-detection/
│-- 📜 phishing_detection.ipynb     # Jupyter Notebook with model implementation
│-- 📜 phishing_detection.py        # Python script for execution
│-- 📜 requirements.txt             # Dependencies list
│-- 📂 model/                        # Trained models (if available)
│-- 📂 data/                         # Datasets used for training
│-- 📂 images/                       # Screenshots and visualizations
```

## 📈 Model Performance

The phishing URL detection model has been evaluated on various metrics including:

- **Accuracy**: Measures overall correctness.
- **Precision & Recall**: Evaluates phishing vs legitimate classification performance.
- **F1-Score**: Balances precision and recall for reliable evaluation.

## 🔗 Model Link

You can access and use the trained model from Hugging Face here: https\://huggingface.co/spaces/eddiebee/phishing\_detection\_model\_playground/tree/main

## 🤝 Contribution Guidelines

We welcome contributions to enhance the project. To contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`
3. Make your changes and commit: `git commit -m "Added new feature"`
4. Push to GitHub: `git push origin feature-branch`
5. Open a Pull Request for review.

## 🔮 Future Enhancements

- **Integration with Web Browsers**: Implement browser extensions for automatic phishing detection.
- **Deep Learning Models**: Train advanced deep learning models like BERT or GPT for improved classification.
- **Threat Intelligence API**: Incorporate APIs for real-time blacklist verification.
- **Mobile App**: Develop a lightweight app for checking URLs on mobile devices.

## 🙌 Acknowledgments

- Thanks to open-source datasets and libraries that made this project possible.
- Inspired by academic research in cybersecurity and phishing detection.

## 📞 Contact

For any queries or contributions, feel free to reach out:

- **Email**: aryankaminwar@gmail.com 


