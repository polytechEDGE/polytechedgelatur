"""
Database of college website URLs
"""

COLLEGE_URLS = {
    # Government Colleges
    "Government College of Engineering, Amravati": "https://gcoea.ac.in",
    "Government College of Engineering, Aurangabad": "https://geca.ac.in",
    "Government College of Engineering, Karad": "https://www.gcekarad.ac.in",
    "Government College of Engineering, Pune": "https://www.coep.org.in",
    "Government College of Engineering, Nagpur": "https://gcoea.ac.in",
    "Government College of Engineering, Jalgaon": "https://www.gcoej.ac.in",
    "Government College of Engineering and Research, Avasari Khurd": "https://gcoeavasari.ac.in",
    "Government College of Engineering, Chandrapur": "https://gcoec.ac.in",
    "Government Polytechnic, Mumbai": "https://gpmumbai.ac.in",
    "Government Polytechnic, Pune": "https://gppune.ac.in",
    "Government Polytechnic, Nagpur": "https://gpnagpur.ac.in",
    
    # Autonomous Colleges
    "Veermata Jijabai Technological Institute, Mumbai": "https://www.vjti.ac.in",
    "Sardar Patel College of Engineering, Mumbai": "https://www.spce.ac.in",
    "Walchand College of Engineering, Sangli": "https://www.walchandsangli.ac.in",
    "Shri Guru Gobind Singhji Institute of Engineering and Technology, Nanded": "https://www.sggs.ac.in",
    "Dr. Babasaheb Ambedkar Technological University, Lonere": "https://dbatu.ac.in",
    
    # Private Colleges
    "K. J. Somaiya College of Engineering, Mumbai": "https://kjsce.somaiya.edu",
    "D. J. Sanghvi College of Engineering, Mumbai": "https://www.djsce.ac.in",
    "Pune Institute of Computer Technology, Pune": "https://pict.edu",
    "Maharashtra Institute of Technology, Pune": "https://mitwpu.edu.in",
    "Vishwakarma Institute of Technology, Pune": "https://www.vit.edu",
    "College of Engineering, Pune": "https://www.coep.org.in",
    "Shri Ramdeobaba College of Engineering and Management, Nagpur": "https://www.rknec.edu",
    "Fr. Conceicao Rodrigues College of Engineering, Mumbai": "https://www.frcrce.ac.in",
    "Sinhgad College of Engineering, Pune": "https://scoe.sinhgad.edu",
    "Pimpri Chinchwad College of Engineering, Pune": "https://www.pccoepune.com",
    
    # Default entries for colleges with unknown URLs
    "DEFAULT": "https://dtemaharashtra.gov.in"
}

def get_college_url(college_name):
    """Get the URL for a college, return default if not found"""
    for key, url in COLLEGE_URLS.items():
        if key.lower() in college_name.lower():
            return url
    return COLLEGE_URLS.get("DEFAULT") 