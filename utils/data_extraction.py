import os
import pandas as pd
import re
from PyPDF2 import PdfReader

def extract_data_from_pdfs(pdf_dir):
    """Extract cutoff data from PDF files."""
    data = []
    current_college = None
    current_branch = None
    current_year = None
    
    # Get list of PDF files
    pdf_files = [f for f in os.listdir(pdf_dir) if f.endswith('.pdf')]
    print(f"\nFound {len(pdf_files)} PDF files:")
    for f in pdf_files:
        print(f"- {f}")
    
    for pdf_file in pdf_files:
        print(f"\nProcessing {pdf_file}...")
        pdf_path = os.path.join(pdf_dir, pdf_file)
        
        # Extract year from filename
        year_match = re.search(r'(\d{4})', pdf_file)
        if year_match:
            current_year = year_match.group(1)
            print(f"Extracted year: {current_year}")
        
        # Read PDF
        reader = PdfReader(pdf_path)
        print(f"PDF has {len(reader.pages)} pages")
        
        for page_num, page in enumerate(reader.pages, 1):
            print(f"\nProcessing page {page_num}...")
            text = page.extract_text()
            lines = text.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Skip header lines
                if any(x in line for x in ['GOVERNMENT OF MAHARASHTRA', 'State Common Entrance Test Cell', 'Provisional Cutoff List', 'Published On']):
                    continue
                
                # Extract college name and location
                if re.match(r'^\d{4}\s+', line):
                    # Look for college name pattern
                    college_match = re.match(r'^\d{4}\s+(.*?)\s*\((.*?)\)', line)
                    if college_match:
                        current_college = college_match.group(1).strip()
                        college_type = college_match.group(2).strip()
                        print(f"Found college: {current_college} ({college_type})")
                        
                        # Determine college type
                        if 'Government' in college_type:
                            college_type = 'Government'
                        elif 'Autonomous' in college_type:
                            college_type = 'Autonomous'
                        else:
                            college_type = 'Private'
                        
                        # Extract location
                        location = 'Other'
                        locations = ['Mumbai', 'Pune', 'Nagpur', 'Nashik', 'Aurangabad', 'Solapur', 'Kolhapur', 'Sangli', 'Satara', 'Ratnagiri', 'Thane', 'Navi Mumbai', 'Amravati']
                        for loc in locations:
                            if loc in current_college:
                                location = loc
                                break
                        print(f"Location: {location}")
                
                # Extract branch
                elif 'Course Name :' in line:
                    branch_match = re.search(r'Course Name :\s*(.*)', line)
                    if branch_match:
                        current_branch = branch_match.group(1).strip()
                        print(f"Found branch: {current_branch}")
                
                # Extract cutoff
                elif re.match(r'Stage-[IVX]+', line):
                    # Look for cutoff percentage in the next line
                    if line_num + 1 < len(lines):
                        next_line = lines[line_num].strip()
                        cutoff_match = re.search(r'\((\d+\.\d+)%\)', next_line)
                        if cutoff_match:
                            cutoff = float(cutoff_match.group(1))
                            print(f"Found cutoff: {cutoff}%")
                            
                            # Extract category
                            category = 'General'
                            if 'GOPEN' in line:
                                category = 'General'
                            elif 'GSC' in line:
                                category = 'SC'
                            elif 'GST' in line:
                                category = 'ST'
                            elif 'GSEBC' in line:
                                category = 'SEBC'
                            elif 'GOBC' in line:
                                category = 'OBC'
                            elif 'LOPEN' in line:
                                category = 'General'
                            elif 'LSC' in line:
                                category = 'SC'
                            elif 'LST' in line:
                                category = 'ST'
                            elif 'LSEBC' in line:
                                category = 'SEBC'
                            elif 'LOBC' in line:
                                category = 'OBC'
                            
                            print(f"Category: {category}")
                            
                            if current_college and current_branch:
                                data.append({
                                    'college_name': current_college,
                                    'branch': current_branch,
                                    'category': category,
                                    'cutoff': cutoff,
                                    'year': current_year,
                                    'college_type': college_type,
                                    'location': location
                                })
                                print(f"Added data for {current_college} - {current_branch}")
    
    print(f"\nTotal records extracted: {len(data)}")
    return pd.DataFrame(data)

def clean_data(df):
    """Clean and process the extracted data."""
    if df.empty:
        print("Warning: No data was extracted from PDFs.")
        return df
    
    print(f"\nInitial data shape: {df.shape}")
    
    # Remove duplicates
    df = df.drop_duplicates()
    print(f"After removing duplicates: {df.shape}")
    
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
    
    print("\nData summary:")
    print(f"Total records: {len(df)}")
    print(f"Unique colleges: {df['college_name'].nunique()}")
    print(f"Unique branches: {df['branch'].nunique()}")
    print(f"Unique locations: {df['location'].nunique()}")
    
    return df

def process_pdfs(pdf_dir, output_dir):
    """Process PDF files and save extracted data."""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract data from PDFs
    df = extract_data_from_pdfs(pdf_dir)
    
    # Save raw data
    raw_output = os.path.join(output_dir, 'raw_cutoff_data.csv')
    df.to_csv(raw_output, index=False)
    print(f"\nRaw data saved to {raw_output}")
    
    # Clean data
    print("\nCleaning and processing data...")
    df_cleaned = clean_data(df)
    
    # Save cleaned data
    cleaned_output = os.path.join(output_dir, 'cleaned_cutoff_data.csv')
    df_cleaned.to_csv(cleaned_output, index=False)
    print(f"Cleaned data saved to {cleaned_output}")
    
    print(f"\nExtracted {len(df_cleaned)} records from {len(os.listdir(pdf_dir))} PDF files")
    print("\nSample of extracted data:")
    print(df_cleaned.head())
    
    return df_cleaned
