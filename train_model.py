import os
import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import OneHotEncoder

def train_prediction_model(data_path=None):
    """
    Train a model to predict college cutoffs
    """
    # Set default data path if not provided
    if data_path is None:
        # Try to use raw_cutoff_data.csv first, then fall back to cleaned_cutoff_data.csv
        raw_data_path = os.path.join('data', 'raw_cutoff_data.csv')
        cleaned_data_path = os.path.join('data', 'cleaned_cutoff_data.csv')
        
        if os.path.exists(raw_data_path):
            data_path = raw_data_path
            print(f"Using raw data from {data_path}")
        else:
            data_path = cleaned_data_path
            print(f"Using cleaned data from {data_path}")
    
    # Check if file exists
    if not os.path.exists(data_path):
        print(f"Error: Data file '{data_path}' not found.")
        print("Please run process_pdfs.py first to extract data from PDFs.")
        return None, None
    
    # Load the data
    try:
        print(f"Attempting to load data from {data_path}...")
        df = pd.read_csv(data_path)
        print(f"Successfully loaded data with {len(df)} records")
    except Exception as e:
        print(f"Error loading data: {str(e)}")
        return None, None
    
    if df.empty:
        print("Error: The data file is empty.")
        return None, None
    
    # If using raw data, clean it
    if 'raw_cutoff_data.csv' in data_path:
        print("Cleaning raw data...")
        # Perform basic cleaning operations
        # Remove duplicates
        df = df.drop_duplicates()
        print(f"After removing duplicates: {df.shape[0]} records")
        
        # Convert cutoff to float
        df['cutoff'] = pd.to_numeric(df['cutoff'], errors='coerce')
        
        # Fill missing values
        df['year'] = df['year'].fillna('2022')
        df['college_type'] = df['college_type'].fillna('Private')
        df['location'] = df['location'].fillna('Other')
        
        # Clean branch names
        df['branch'] = df['branch'].str.strip()
        
        # Clean college names
        df['college_name'] = df['college_name'].str.strip()
        
        print(f"After cleaning: {df.shape[0]} records")
    
    print(f"Training model with {len(df)} records...")
    
    # Prepare features and target
    features = df[['college_name', 'branch', 'category', 'college_type', 'year']]
    target = df['cutoff']
    
    # One-hot encode categorical features
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    encoded_features = encoder.fit_transform(features)
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        encoded_features, target, test_size=0.2, random_state=42
    )
    
    # Train a Random Forest model
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"Model Training Score: {train_score:.4f}")
    print(f"Model Testing Score: {test_score:.4f}")
    
    # Create models directory if it doesn't exist
    models_dir = 'models'
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
    
    # Save the model and encoder
    model_path = os.path.join(models_dir, 'college_predictor_model.pkl')
    encoder_path = os.path.join(models_dir, 'feature_encoder.pkl')
    
    try:
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"Model saved to {model_path}")
    except Exception as e:
        print(f"Error saving model: {str(e)}")
    
    try:
        with open(encoder_path, 'wb') as f:
            pickle.dump(encoder, f)
        print(f"Encoder saved to {encoder_path}")
    except Exception as e:
        print(f"Error saving encoder: {str(e)}")
    
    return model, encoder

if __name__ == "__main__":
    train_prediction_model()
