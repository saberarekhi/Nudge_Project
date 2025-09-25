Q1 Project: A Crowdsourcing Platform for Civic Participation Research
This repository contains the source code for the Progressive Web App (PWA) used in the field experiment detailed in the academic paper: "Incentives, Nudges, and the Sustainability of Urban Crowdsourcing: A Randomized Controlled Trial."

This platform was designed as the primary instrument for an 8-week study investigating the effects of different motivational interventions on citizen engagement in urban issue reporting.

🚀 Features
The platform provides a simple and intuitive interface for citizens to:

Submit New Reports: Users can report urban issues with a description, an optional photo, and a precise location.

Geolocation: Location can be tagged automatically using the device's GPS or selected manually from an interactive map.

Personal Dashboard: Each user has a personal dashboard to view their recent submissions.

Performance Statistics: The dashboard displays key performance metrics, including the total number of reports submitted, the number of approved reports, and the overall success rate.

Community Feed: A section on the dashboard shows the latest reports submitted by other users in the community, fostering a sense of collective action.

🔬 About the Research
This web application was central to an 8-week Randomized Controlled Trial (RCT) conducted in Tehran. The study aimed to understand the trade-offs between the quantity, quality, and sustainability of citizen participation under different incentive structures.

Upon registration, 256 participants were randomly assigned to one of four experimental groups:

Control Group (C): Had access to the baseline platform with no extra features.

Micropayment Group (M): Received a small monetary reward for each validated report.

Nudge Group (N): Received weekly behavioral nudges based on social comparison and goal-setting principles.

Hybrid Group (H): Received both micropayments and weekly nudges.

The platform was designed to track user activity meticulously, providing the raw data for analyzing the effectiveness of each intervention.

🛠️ Setup and Installation
To run this project locally, please follow these steps:

Prerequisites:

Python 3.8+

pip (Python package installer)

Git

Installation:

Clone the repository:

git clone [https://github.com/your-username/q1-project.git](https://github.com/your-username/q1-project.git)
cd q1-project

Create and activate a virtual environment (recommended):

python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

Install the required dependencies:

pip install -r requirements.txt

Run the application:

python app.py

Open your web browser and navigate to http://127.0.0.1:5001 to see the application running.
