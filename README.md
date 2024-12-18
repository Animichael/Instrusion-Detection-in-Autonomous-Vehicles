# Instrusion-Detection-in-Autonomous-Vehicles

### Overview
In this project, I implement Intrusion Detection System (IDS) for autonomous vehicles using the Car Hacking Dataset. The system leverages payload byte analysis to detect malicious activities in vehicle communication networks. It is integrated with a Flask-based web application for seamless interaction and management.

#### Features
The application consists of the following modules:

Dashboard: Provides a centralized view of system activities and performance metrics.
Vehicle Registration: Enables adding and managing vehicle details in the system.
Intrusion Detection: Monitors vehicle communication and identifies potential intrusions in real-time.
Vehicle Status: Displays the current status and health of registered vehicles.
Analytics: Offers insights and visualizations based on the dataset and intrusion detection outcomes.
Settings: Allows configuration of system preferences and security parameters.

##### Dataset
The system is trained using the Car Hacking Dataset, focusing on the payload byte features to detect anomalies.

Technologies Used
Machine Learning: For intrusion detection model development.
Flask: Backend framework for the application.
HTML, CSS, and JavaScript: For the frontend interface.
Python: For data processing, training, and deployment.

##### How It Works
The system processes vehicle communication data and extracts payload byte features.
A trained machine learning model analyzes the data to detect anomalies.
Results are displayed in real-time on the Flask-based application, providing actionable insights and alerts.
