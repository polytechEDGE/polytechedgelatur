import pandas as pd
import numpy as np
from utils.college_urls import get_college_url

def predict_colleges(user_input, model, encoder, cutoff_data):
    """
    Predict colleges based on user input
    
    Parameters:
    - user_input: dict with keys 'marks', 'category', 'branch', 'college_type', 'location'
    - model: trained prediction model
    - encoder: feature encoder
    - cutoff_data: DataFrame with historical cutoff data
    
    Returns:
    - DataFrame with recommended colleges and admission probabilities
    """
    print("\nDebug - User Input:", user_input)
    
    # Apply category-based relaxation
    relaxation = {
        'General': 0,
        'OBC': 5,
        'SC': 10,
        'ST': 12,
        'SEBC': 7,
        'EWS': 2
    }
    
    # Map user category to data category
    category_mapping = {
        'General': 'General',
        'OBC': 'OBC',
        'SC': 'SC',
        'ST': 'ST',
        'SEBC': 'SEBC',
        'EWS': 'EWS'
    }
    
    user_category = category_mapping.get(user_input['category'], 'General')
    adjusted_marks = user_input['marks'] + relaxation.get(user_input['category'], 0)
    print(f"Debug - Adjusted marks: {adjusted_marks} (Category: {user_category})")
    
    # Filter colleges based on user preferences
    filtered_colleges = cutoff_data.copy()
    print(f"Debug - Initial number of colleges: {len(filtered_colleges)}")
    
    # Apply filters more leniently
    if user_input['college_type'] and user_input['college_type'].lower() != "all":
        filtered_colleges = filtered_colleges[
            filtered_colleges['college_type'].str.lower().str.contains(user_input['college_type'].lower(), na=False)
        ]
        print(f"Debug - After college type filter: {len(filtered_colleges)}")
    
    if user_input['location'] and user_input['location'].lower() != "all":
        filtered_colleges = filtered_colleges[
            filtered_colleges['location'].str.lower().str.contains(user_input['location'].lower(), na=False)
        ]
        print(f"Debug - After location filter: {len(filtered_colleges)}")
    
    if user_input['branch'] and user_input['branch'].lower() != "all":
        filtered_colleges = filtered_colleges[
            filtered_colleges['branch'].str.lower().str.contains(user_input['branch'].lower(), na=False)
        ]
        print(f"Debug - After branch filter: {len(filtered_colleges)}")
    
    # For each college in the filtered list, predict the cutoff
    results = []
    
    # Get unique college-branch combinations
    unique_college_branches = filtered_colleges.drop_duplicates(['college_name', 'branch'])
    
    # Get available years in the data
    available_years = cutoff_data['year'].unique()
    year_weights = {
        '2024': 0.7,  # More weight to recent data
        '2022': 0.3   # Less weight to older data
    }
    
    for _, college in unique_college_branches.iterrows():
        # Prepare input for prediction
        college_input = {
            'college_name': college['college_name'],
            'branch': college['branch'],
            'category': user_category,  # Use mapped category
            'college_type': college['college_type'],
            'year': max(available_years) if len(available_years) > 0 else "2024"
        }
        
        # Analyze historical trend for this college-branch
        college_history = filtered_colleges[
            (filtered_colleges['college_name'] == college['college_name']) & 
            (filtered_colleges['branch'] == college['branch'])
        ]
        
        # Check if we have historical data for this college-branch combination
        has_history = len(college_history) > 1 and len(college_history['year'].unique()) > 1
        
        try:
            # Convert to DataFrame for encoding
            input_df = pd.DataFrame([college_input])
            
            # Encode features
            encoded_input = encoder.transform(input_df)
            
            # Predict cutoff
            predicted_cutoff = model.predict(encoded_input)[0]
            
            # Analyze trend if historical data is available
            trend_factor = 1.0  # Default, no adjustment
            if has_history:
                # Calculate weighted average of historical data
                weighted_cutoff = 0
                total_weight = 0
                
                for year in college_history['year'].unique():
                    year_data = college_history[college_history['year'] == year]
                    if not year_data.empty:
                        year_cutoff = year_data['cutoff'].mean()
                        weighted_cutoff += year_cutoff * year_weights.get(year, 0.5)
                        total_weight += year_weights.get(year, 0.5)
                
                if total_weight > 0:
                    weighted_cutoff = weighted_cutoff / total_weight
                    # Adjust prediction based on trend (smoothing)
                    predicted_cutoff = (predicted_cutoff + weighted_cutoff) / 2
            
            # Calculate mark difference
            mark_difference = adjusted_marks - predicted_cutoff
            
            # New probability calculation based on relationship between marks and cutoff
            if mark_difference >= 0:
                # User's marks are higher than cutoff - higher probability
                # Start at 75% and go up to 99% based on how much higher the marks are
                probability = 75 + min(24, mark_difference * 2.4)
            else:
                # User's marks are lower than cutoff - lower probability
                # For marks below cutoff, probability falls more steeply
                if mark_difference > -10:  # Within 10 percent
                    probability = max(1, 75 + mark_difference * 5)  # Falls faster from 75%
                else:
                    probability = max(1, 25 + (mark_difference + 10) * 2.5)  # Falls even faster below 25%
            
            # Apply trend factor (increasing or decreasing trend in cutoffs)
            if has_history:
                years_sorted = sorted(college_history['year'].unique())
                if len(years_sorted) >= 2:
                    earliest_year = min(years_sorted)
                    latest_year = max(years_sorted)
                    
                    earliest_cutoff = college_history[college_history['year'] == earliest_year]['cutoff'].mean()
                    latest_cutoff = college_history[college_history['year'] == latest_year]['cutoff'].mean()
                    
                    if earliest_cutoff != 0 and not np.isnan(earliest_cutoff):
                        cutoff_change = (latest_cutoff - earliest_cutoff) / earliest_cutoff
                        
                        # If cutoffs are trending up, reduce probability slightly
                        if cutoff_change > 0.05:  # More than 5% increase
                            probability = max(1, probability * 0.9)  # Reduce by 10%
                        # If cutoffs are trending down, increase probability slightly
                        elif cutoff_change < -0.05:  # More than 5% decrease
                            probability = min(99, probability * 1.1)  # Increase by 10%
            
            # Calculate cutoff trend information
            cutoff_trend = "stable"
            trend_percentage = 0
            if has_history and len(years_sorted) >= 2:
                if earliest_cutoff != 0 and not np.isnan(earliest_cutoff) and not np.isnan(latest_cutoff):
                    trend_percentage = round(((latest_cutoff - earliest_cutoff) / earliest_cutoff) * 100, 1)
                    if trend_percentage > 1:
                        cutoff_trend = "increasing"
                    elif trend_percentage < -1:
                        cutoff_trend = "decreasing"
            
            # Get college website URL
            college_url = get_college_url(college['college_name'])
            
            results.append({
                'college_name': college['college_name'],
                'branch': college['branch'],
                'location': college['location'],
                'college_type': college['college_type'],
                'predicted_cutoff': round(predicted_cutoff, 2),
                'adjusted_marks': round(adjusted_marks, 2),
                'probability': round(probability, 1),
                'year': str(college_input['year']),  # Include year in results
                'college_url': college_url,
                'cutoff_trend': cutoff_trend,
                'trend_percentage': trend_percentage,
                'user_marks': user_input['marks'],
                'user_category': user_input['category'],
                'mark_difference': round(mark_difference, 2)
            })
        except Exception as e:
            print(f"Debug - Error predicting for {college['college_name']}: {str(e)}")
            continue
    
    # Convert to DataFrame and sort by probability
    if results:
        results_df = pd.DataFrame(results)
        results_df = results_df.sort_values('probability', ascending=False)
        print(f"Debug - Found {len(results_df)} matching colleges")
        return results_df
    else:
        print("Debug - No matching colleges found")
        return pd.DataFrame()
