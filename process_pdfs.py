import os
import sys
import pandas as pd
from utils.data_extraction import extract_data_from_pdfs, clean_data

def main():
    # Path to PDF directory
    pdf_dir = os.path.join('data', 'pdf')
    
    # Check if directory exists
    if not os.path.exists(pdf_dir):
        print(f"Error: Directory '{pdf_dir}' does not exist.")
        print("Please create this directory and place your PDF files there.")
        sys.exit(1)
    
    # Get list of PDF files
    pdf_files = [f for f in os.listdir(pdf_dir) if f.lower().endswith('.pdf')]
    
    if not pdf_files:
        print(f"Error: No PDF files found in '{pdf_dir}'.")
        print("Please add your DSE cutoff PDF files to this directory.")
        sys.exit(1)
    
    print(f"Found {len(pdf_files)} PDF files:")
    for pdf in pdf_files:
        print(f" - {pdf}")
    
    # Extract data from PDFs
    print("\nExtracting data from PDFs...")
    cutoff_data = extract_data_from_pdfs(pdf_dir)
    
    # Save raw extracted data
    raw_data_path = os.path.join('data', 'raw_cutoff_data.csv')
    cutoff_data.to_csv(raw_data_path, index=False)
    print(f"Raw data saved to {raw_data_path}")
    print(f"Raw data records: {len(cutoff_data)}")
    
    # Clean the data
    print("\nCleaning and processing data...")
    cleaned_data = clean_data(cutoff_data)
    
    # Save cleaned data
    cleaned_data_path = os.path.join('data', 'cleaned_cutoff_data.csv')
    
    # Verify that the data is being properly saved
    print(f"Cleaned data records before saving: {len(cleaned_data)}")
    
    # Force delete the old file if it exists to avoid permission issues
    if os.path.exists(cleaned_data_path):
        try:
            os.remove(cleaned_data_path)
            print(f"Removed existing cleaned data file.")
        except Exception as e:
            print(f"Warning: Could not remove existing file: {str(e)}")
    
    # Save the cleaned data
    cleaned_data.to_csv(cleaned_data_path, index=False)
    
    # Verify that the file was saved correctly
    if os.path.exists(cleaned_data_path):
        # Read the file back to verify the content
        verify_data = pd.read_csv(cleaned_data_path)
        print(f"Verified cleaned data saved with {len(verify_data)} records.")
    else:
        print("ERROR: Failed to save cleaned data file!")
    
    print(f"Cleaned data saved to {cleaned_data_path}")
    print(f"\nExtracted {len(cleaned_data)} records from {len(pdf_files)} PDF files")
    print("\nSample of extracted data:")
    print(cleaned_data.head())
    
    return cleaned_data

if __name__ == "__main__":
    main()
