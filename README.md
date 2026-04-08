## AI Web Application Firewall (WAF) API
1. Overview

   This project implements an AI-driven Web Application Firewall (WAF) using a machine learning model based on Random Forest for detecting and blocking malicious HTTP requests in real time.

   The system operates as a reverse proxy built with Flask, intercepting incoming requests, extracting security-related features, and classifying traffic as either benign or malicious before forwarding it to the      backend application.

   The primary goal is to provide a lightweight, privacy-preserving intrusion detection mechanism without relying on payload decryption or signature-based rules.

2. System Architecture

   The system consists of the following components:

   Client: Sends HTTP requests
   WAF Proxy (Flask API): Intercepts and analyzes requests
   Machine Learning Model: Random Forest classifier for attack detection
   Backend Server: Target web application (e.g., DVWA)
   Workflow
   Client sends HTTP request to WAF
   WAF preprocesses and normalizes input
   Feature extraction is applied
   Model predicts attack probability
   If malicious → block request (HTTP 403)
   If benign → forward request to backend server

3. Features
   
   3.1 Statistical Features
      
      Request length
      Shannon entropy
      Chunk-based entropy
      Ratio of special characters
      Digit ratio
      Indicators for SQLi, XSS, and path traversal

   3.2 Advanced Security Features

      SQL keyword frequency and ratio
      XSS pattern detection
      Command injection indicators
      Logical injection patterns (e.g., 1=1, true)
      Obfuscation detection:
      URL encoding
      Hex encoding
      Unicode encoding
      Base64-like patterns
      Mixed-case obfuscation

3.3 Header Anomaly Features

      Missing User-Agent or Referer
      Suspicious scanning tools (e.g., sqlmap, nikto)
      Abnormally long tokens
      Excessive query parameters
      Unusual HTTP methods (PUT, DELETE, TRACE, CONNECT)

4. Data Preprocessing

   The preprocessing pipeline includes:
      
   URL decoding and HTML entity decoding
   Removal of non-printable characters
   Lowercasing normalization
   Concatenation of:
   Request path
   Query string
   Request body
   HTTP headers

5. Machine Learning Model

   The detection engine uses a Random Forest classifier trained on flow-based and payload-derived features.
   
   Key Characteristics
   Ensemble-based classification
   Robust to noise and feature variation
   Suitable for real-time inference
   Prediction
   
   The model outputs a probability score:
   
   P(attack) = probability of malicious request
   
   A threshold is applied:
   
   If P > 0.45 → request is blocked
   Otherwise → request is allowed

6. Request Handling Logic

   Allowed Requests
   Static resources (CSS, JS, images)
   Known benign patterns (e.g., DVWA test inputs)
   Requests with low attack probability
   Blocked Requests
   Requests exceeding the detection threshold
   Detected attack types:
   SQL Injection
   Cross-Site Scripting (XSS)
   Path Traversal
   Command Injection
   
   Blocked requests receive a custom HTTP 403 response page.

7. Logging Mechanism

   All detected attacks are logged into:
   
   waf_logs.txt
   
   Each log entry includes:
   
   Timestamp
   Client IP address
   Full request payload

8. Reverse Proxy Mechanism

   The WAF forwards legitimate requests to the backend server using the requests library.
   
   Backend Configuration
   Default target: DVWA (Damn Vulnerable Web Application)
   URL: http://127.0.0.1
   Header Handling
   Removes restricted headers:
   content-encoding
   content-length
   transfer-encoding
   connection

9. Running the Application

   Requirements
   Python 3.x
   Required libraries:
   Flask
   scikit-learn
   numpy
   requests
   joblib
   colorama

   Install dependencies:
   
   pip install -r requirements.txt
   Run the WAF
   python app.py
   Default Configuration
   Host: 0.0.0.0
   Port: 8080
   Backend: 127.0.0.1

10. Project Structure

      /models
          final_model.pkl
      /src
          app.py
      /logs
          waf_logs.txt
      README.md
      requirements.txt

12. Advantages

   Real-time detection using machine learning
   No dependency on signature-based rules
   Privacy-preserving (no payload decryption required)
   Modular feature engineering pipeline
   Easily extensible for additional attack patterns

12. Limitations
    
   Threshold-based detection may require tuning
   Potential false positives in edge cases
   Does not model temporal request sequences
   Dependent on feature engineering quality

13. Future Work
   Integration with deep learning models (LSTM, GRU)
   Adaptive threshold tuning
   Real-time streaming and distributed deployment
   Explainable AI (feature importance analysis)
   Integration with SIEM systems

14. License

   This project is intended for research and educational purposes only.
