import requests
import json
import streamlit as st

# Replace with your Tenable.io API credentials
ACCESS_KEY = 'YOUR_ACCESS_KEY'
SECRET_KEY = 'YOUR_SECRET_KEY'
BASE_URL = 'https://cloud.tenable.com/'

def get_vulnerabilities(min_cvss_score=7.0):
    """
    Retrieves vulnerabilities from Tenable.io and filters them by CVSS score.

    Args:
        min_cvss_score: The minimum CVSS score to filter by (default: 7.0).

    Returns:
        A list of vulnerability dictionaries. Returns an empty list on error.
    """
    url = f'{BASE_URL}vulns'
    headers = {
        'X-ApiKeys': f'accessKey={ACCESS_KEY};secretKey={SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    params = {
        'severity': f'{min_cvss_score}+'  # Filter for vulnerabilities with CVSS >= min_cvss_score
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        vulnerabilities = response.json()['vulnerabilities']
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        st.error(f'Error retrieving vulnerabilities: {e}')
        return []
    except json.JSONDecodeError as e:
        st.error(f"Error decoding JSON response: {e}. Response text: {response.text}")
        return []

def display_vulnerability_details(vulnerabilities):
    """
    Displays details for each vulnerability using Streamlit.

    Args:
        vulnerabilities: A list of vulnerability dictionaries.
    """
    if not vulnerabilities:
        st.info("No vulnerabilities found.")
        return

    for vuln in vulnerabilities:
        st.markdown('---')
        st.subheader(f'CVE: {vuln.get("cve", "N/A")}')
        st.write(f'CVSS Score: {vuln.get("cvss_base_score", "N/A")}')
        st.write(f'Severity: {vuln.get("severity", "N/A")}')
        st.write(f'Synopsis: {vuln.get("synopsis", "N/A")}')
        st.write(f'Solution: {vuln.get("solution", "N/A")}')

def main():
    """
    Main function to run the vulnerability mitigation tool with Streamlit.
    """
    st.title("Vulnerability Mitigation Tool")

    # Input for CVSS score
    min_cvss_score = st.slider("Minimum CVSS Score", min_value=0.0, max_value=10.0, value=7.0, step=0.1)

    # Button to trigger the vulnerability retrieval
    if st.button("Get Vulnerabilities"):
        vulnerabilities = get_vulnerabilities(min_cvss_score)
        display_vulnerability_details(vulnerabilities)

if __name__ == "__main__":
    main()
