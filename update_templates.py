import os
import re

def update_template(file_path):
    """Replace the navbar in a template with the include statement."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        # Skip files that already include the header component
        if "{% include 'components/header.html' %}" in content:
            print(f"Skipping {file_path} (already updated)")
            return False
        
        # Check if the file uses Bootstrap
        if "bootstrap" not in content.lower():
            print(f"Skipping {file_path} (not using Bootstrap)")
            return False
        
        # Find the body tag and add our include statement after it
        body_pattern = r'<body[^>]*>'
        if not re.search(body_pattern, content):
            print(f"No body tag found in {file_path}")
            return False
        
        # Replace after body tag
        body_replacement = '<body data-bs-theme="dark">\n    <!-- Include the reusable header/navbar component -->\n    {% include \'components/header.html\' %}\n'
        updated_content = re.sub(body_pattern, body_replacement, content)
        
        # Try to remove existing nav if present
        nav_pattern = r'<nav.*?</nav>'
        updated_content = re.sub(nav_pattern, '', updated_content, flags=re.DOTALL, count=1)
        
        # Write the updated content back to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(updated_content)
        
        print(f"Updated {file_path}")
        return True
    
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

def main():
    templates_dir = 'templates'
    updated_count = 0
    skipped_count = 0
    
    # Exclude these files and directories
    exclusions = {'components', 'base.html', 'error.html'}
    
    # Get all HTML files in the templates directory
    html_files = []
    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if (file.endswith('.html') or file.endswith('.HTML')) and file not in exclusions:
                if os.path.basename(root) in exclusions:
                    continue
                html_files.append(os.path.join(root, file))
    
    print(f"Found {len(html_files)} HTML files to process")
    
    # Process files
    for file_path in sorted(html_files):
        if update_template(file_path):
            updated_count += 1
        else:
            skipped_count += 1
    
    print(f"\nSummary:")
    print(f"  Updated: {updated_count} files")
    print(f"  Skipped: {skipped_count} files")

if __name__ == "__main__":
    main() 