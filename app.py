import streamlit as st
import pandas as pd
import joblib

# 1. Page Configuration
st.set_page_config(
    page_title="SQL Injection Classifier",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️SQL Injection Classifier")
st.markdown("Detect malicious SQL statements and exfiltration attempts using your pre-trained model.")

# 2. Load the pre-saved Model and Vectorizer (.pkl files)
@st.cache_resource
def load_saved_artifacts():
    # Update these filenames to match whatever you named your saved files
    model = joblib.load("sql_model.pkl")       # or your model's filename
    vectorizer = joblib.load("tfidf_vectorizer.pkl") # or your vectorizer's filename
    return model, vectorizer

with st.spinner("Loading pre-trained model and vectorizer..."):
    model, vectorizer = load_saved_artifacts()

st.success("Model loaded successfully from `.pkl`!")

# 3. Sidebar Navigation
app_mode = st.sidebar.selectbox("Choose Mode", ["Single Query Inspector", "Batch Log Analyzer"])

# --- Mode 1: Single Query Inspector ---
if app_mode == "Single Query Inspector":
    st.header("🔍 Single Query Analysis")
    st.markdown("Test individual SQL statements to check for potential injection attacks.")
    
    default_query = "SELECT * FROM users WHERE id = 1' OR '1'='1 --;"
    user_query = st.text_area("Enter SQL Query:", value=default_query, height=100)
    
    threshold = st.slider("Malicious Probability Threshold", 0.0, 1.0, 0.5, 0.05)
    
    if st.button("Analyze Query"):
        if user_query.strip():
            # Vectorize using the loaded vectorizer and predict using the loaded model
            query_vec = vectorizer.transform([user_query])
            prob_malicious = model.predict_proba(query_vec)[0][1]
            
            is_malicious = prob_malicious >= threshold
            
            # Display results
            col1, col2 = st.columns(2)
            with col1:
                if is_malicious:
                    st.error(f"🚨 **Verdict: MALICIOUS**")
                else:
                    st.success(f"✅ **Verdict: BENIGN**")
            with col2:
                st.metric(label="Malicious Probability Score", value=f"{prob_malicious:.4f}")
        else:
            st.warning("Please enter a valid SQL query.")

# --- Mode 2: Batch Log Analyzer ---
elif app_mode == "Batch Log Analyzer":
    st.header("📂 Batch Database Audit Log Analyzer")
    st.markdown("Upload a CSV file containing database query logs to scan them in bulk.")
    
    uploaded_file = st.file_uploader("Upload CSV file (must contain a query column)", type=["csv"])
    
    if uploaded_file is not None:
        batch_df = pd.read_csv(uploaded_file)
        st.write("Preview of uploaded data:", batch_df.head(3))
        
        query_column = st.selectbox("Select the column containing SQL queries:", batch_df.columns)
        
        if st.button("Run Batch Scan"):
            with st.spinner("Scanning queries..."):
                queries_list = batch_df[query_column].astype(str).tolist()
                X_batch_vec = vectorizer.transform(queries_list)
                probabilities = model.predict_proba(X_batch_vec)[:, 1]
                
                batch_df["Malicious_Probability"] = probabilities
                batch_df["Prediction"] = ["MALICIOUS" if p >= 0.5 else "BENIGN" for p in probabilities]
                
            st.subheader("Scan Results Summary")
            malicious_count = (batch_df["Prediction"] == "MALICIOUS").sum()
            benign_count = (batch_df["Prediction"] == "BENIGN").sum()
            
            col1, col2 = st.columns(2)
            col1.metric("Flagged Malicious Queries", malicious_count)
            col2.metric("Benign Queries", benign_count)
            
            st.dataframe(batch_df)
            
            csv_output = batch_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Scan Results as CSV",
                data=csv_output,
                file_name="ueba_scan_results.csv",
                mime="text/csv",
            )