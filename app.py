import pandas as pd
import random
# Removed: from sklearn.model_selection import train_test_split  # Not needed for data generation
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import warnings
warnings.filterwarnings("ignore")
import streamlit as st  # Import Streamlit

# 1. Data Collection
#   -  Simulate vulnerability data (in a real-world scenario, this would come from a database or API)
def generate_vulnerability_data(num_vulnerabilities=1000):
    """
    Generates a synthetic dataset of vulnerabilities.

    Args:
        num_vulnerabilities: The number of vulnerabilities to generate.

    Returns:
        A pandas DataFrame containing the vulnerability data.
    """
    data = {
        'CVE_ID': [f'CVE-{2024}-{i}' for i in range(1, num_vulnerabilities + 1)],
        'CVSS_Severity': [random.choice(['Low', 'Medium', 'High', 'Critical']) for _ in range(num_vulnerabilities)],
        'Exploitability': [random.uniform(0, 10) for _ in range(num_vulnerabilities)],
        'Impact': [random.uniform(0, 10) for _ in range(num_vulnerabilities)],
        'Attack_Vector': [random.choice(['Network', 'Adjacent Network', 'Local', 'Physical']) for _ in range(num_vulnerabilities)],
        'Easily_Accessible': [random.choice([True, False]) for _ in range(num_vulnerabilities)], # Changed to English
        'Remediation_Difficulty': [random.choice(['Easy', 'Medium', 'Hard']) for _ in range(num_vulnerabilities)],
        'Short_Description': [f"Vulnerability {i} short description" for i in range(1, num_vulnerabilities + 1)],  # Added short description
        'Long_Description': [f"Vulnerability {i} long description. This is a more detailed explanation of the vulnerability." for i in range(1, num_vulnerabilities + 1)],  # Added long description
        'Exploitable': [random.choice([0, 1]) for _ in range(num_vulnerabilities)]
    }
    df = pd.DataFrame(data)
    return df

# 2. Feature Engineering and Data Preprocessing
def preprocess_vulnerability_data(df):
    """
    Preprocesses the vulnerability data for machine learning.

    Args:
        df: A pandas DataFrame containing the vulnerability data.

    Returns:
        A pandas DataFrame containing the preprocessed data, ready for model training.
    """
    # Convert categorical variables to numerical using one-hot encoding
    df = pd.get_dummies(df, columns=['CVSS_Severity', 'Attack_Vector', 'Remediation_Difficulty'])

    # Drop the CVE_ID, Short_Description, and Long_Description (they're not useful for prediction)
    df = df.drop(['CVE_ID', 'Short_Description', 'Long_Description'], axis=1)
    return df

# 3. Model Training
def train_risk_assessment_model(df):
    """
    Trains a machine learning model to assess the risk of vulnerabilities.

    Args:
        df: A pandas DataFrame containing the preprocessed vulnerability data.

    Returns:
        A trained machine learning model (RandomForestClassifier).
    """
    # Separate features and target variable
    X = df.drop('Exploitable', axis=1)
    y = df['Exploitable']

    # Split data into training and testing sets
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Choose a model (Random Forest is a good starting point)
    model = RandomForestClassifier(random_state=42, class_weight='balanced')

    # Train the model
    model.fit(X_train, y_train)
    return model, X_test, y_test

# 4. Model Evaluation
def evaluate_model(model, X_test, y_test):
    """
    Evaluates the performance of the trained machine learning model.

    Args:
        model: A trained machine learning model.
        X_test: The test data
        y_test: The test labels

    Returns:
        None. Prints the accuracy and classification report.
    """
    # Make predictions on the test set
    y_pred = model.predict(X_test)

    # Evaluate the model
    accuracy = accuracy_score(y_test, y_pred)
    st.write(f'Accuracy: {accuracy:.2f}')  # Use st.write for Streamlit
    st.text(classification_report(y_test, y_pred)) # Use st.text for Streamlit


# 5. Vulnerability Prioritization
def prioritize_vulnerabilities(model, df, original_df):
    """
    Prioritizes vulnerabilities based on the model's risk assessment, and adds additional info.

    Args:
        model: A trained machine learning model.
        df: A pandas DataFrame containing the preprocessed vulnerability data.
        original_df: The original DataFrame with all columns

    Returns:
        A pandas DataFrame with prioritized vulnerabilities, sorted by risk.
    """
    # Predict the probability of a vulnerability being exploitable
    probas = model.predict_proba(df.drop('Exploitable', axis=1))
    df['Exploitability_Probability'] = probas[:, 1]

    # Combine with the original dataframe to get the extra columns
    prioritized_df = pd.concat([original_df, df['Exploitability_Probability']], axis=1)

    # Prioritize vulnerabilities based on exploitability probability
    prioritized_df = prioritized_df.sort_values(by='Exploitability_Probability', ascending=False)
    return prioritized_df

def main():
    """
    Main function to run the vulnerability assessment and prioritization pipeline.
    """
    st.title("Vulnerability Assessment and Prioritization")  # Title for the Streamlit app

    # 1. Data Collection
    num_vulnerabilities = st.slider("Number of Vulnerabilities to Generate", 100, 2000, 1000)
    vulnerability_data = generate_vulnerability_data(num_vulnerabilities)

    # 2. Feature Engineering and Data Preprocessing
    preprocessed_data = preprocess_vulnerability_data(vulnerability_data.copy())  # Pass a copy to preprocess

    # 3. Model Training
    model, X_test, y_test = train_risk_assessment_model(preprocessed_data)

    # 4. Model Evaluation
    st.subheader("Model Evaluation")
    evaluate_model(model, X_test, y_test)

    # 5. Vulnerability Prioritization
    st.subheader("Prioritized Vulnerabilities")
    prioritized_vulnerabilities = prioritize_vulnerabilities(model, preprocessed_data, vulnerability_data)  # Pass original df
    st.dataframe(prioritized_vulnerabilities)  # Display the prioritized vulnerabilities as a DataFrame

if __name__ == "__main__":
    main()
