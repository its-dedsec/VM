import requests
import streamlit as st
import json

# Base URL for the National Vulnerability Database (NVD) API
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_vulnerabilities_nvd(min_cvss_score=7.0):
    """
    Retrieves vulnerabilities from the National Vulnerability Database (NVD)
    and filters them by CVSS score.

    Args:
        min_cvss_score: The minimum CVSS score to filter by (default: 7.0).

    Returns:
        A list of vulnerability dictionaries. Returns an empty list on error.
    """
    url = f"{NVD_API_BASE_URL}?cvssV3Severity=HIGH&resultsPerPage=2000"  # Limiting to HIGH severity for demonstration
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Filter vulnerabilities based on CVSS v3 score
        filtered_vulnerabilities = []
        for vuln_data in vulnerabilities:
            cve = vuln_data.get("cve")
            if cve:
                cvssv3 = cve.get("metrics", {}).get("cvssMetricV31", [])
                if cvssv3:
                    base_score = cvssv3[0].get("cvssData", {}).get("baseScore", 0)
                    if base_score >= min_cvss_score:
                        filtered_vulnerabilities.append(cve)
        return filtered_vulnerabilities

    except requests.exceptions.RequestException as e:
        st.error(f"Error retrieving vulnerabilities from NVD: {e}")
        return []
    except json.JSONDecodeError as e:
        st.error(f"Error decoding JSON response from NVD: {e}")
        return []
    except KeyError as e:
        st.error(f"Error accessing data in NVD response: {e}")
        return []

def display_vulnerability_details(vulnerabilities):
    """
    Displays details for each vulnerability using Streamlit.

    Args:
        vulnerabilities: A list of vulnerability dictionaries.
    """
    if not vulnerabilities:
        st.info("No vulnerabilities found matching the criteria.")
        return

    for vuln in vulnerabilities:
        st.markdown("---")
        st.subheader(f'CVE ID: {vuln.get("id", "N/A")}')
        
        # Extract CVSS v3 information
        cvssv3 = vuln.get("metrics", {}).get("cvssMetricV31", [])
        if cvssv3:
            base_score = cvssv3[0].get("cvssData", {}).get("baseScore", "N/A")
            severity = cvssv3[0].get("cvssData", {}).get("severity", "N/A")
            st.write(f'CVSS v3 Score: {base_score}')
            st.write(f'Severity: {severity}')
        else:
            st.write("CVSS v3 Score: N/A")
            st.write("Severity: N/A")
            
        summary = vuln.get("descriptions", [])
        if summary:
            st.write(f'Description: {summary[0].get("value", "N/A")}')
        else:
            st.write("Description: N/A")

def main():
    """
    Main function to run the vulnerability mitigation tool with Streamlit,
    using the NVD API.
    """
    st.title("Vulnerability Mitigation Tool (NVD)")

    # Input for CVSS score
    min_cvss_score = st.slider(
        "Minimum CVSS Score", min_value=0.0, max_value=10.0, value=7.0, step=0.1
    )

    # Button to trigger the vulnerability retrieval
    if st.button("Get Vulnerabilities"):
        vulnerabilities = get_vulnerabilities_nvd(min_cvss_score)
        display_vulnerability_details(vulnerabilities)


if __name__ == "__main__":
    main()
