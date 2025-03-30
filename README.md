# PolytechEDGE

PolytechEDGE is a web platform designed to empower polytechnic students to make informed decisions about their future education and career paths.

## Setting Up OAuth for Social Login

The platform supports login and signup via Google and Apple accounts. To set up these authentication methods, follow the instructions below.

### Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" and select "OAuth client ID"
5. Select "Web application" as the application type
6. Add your application name
7. Add authorized JavaScript origins (e.g., `http://localhost:5000`)
8. Add authorized redirect URIs (e.g., `http://localhost:5000/auth/google/callback`)
9. Click "Create" and note your Client ID and Client Secret
10. Copy the `.env.example` file to `.env` and update the values:
    ```
    GOOGLE_CLIENT_ID=your_client_id_here
    GOOGLE_CLIENT_SECRET=your_client_secret_here
    ```

### Apple Sign In Setup (Optional)

1. Go to the [Apple Developer Portal](https://developer.apple.com/)
2. Navigate to "Certificates, Identifiers & Profiles"
3. Register a new identifier for your app with "Sign In with Apple" capability
4. Generate a client secret as documented in [Apple's documentation](https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens)
5. Update your `.env` file with the Apple credentials

If you do not configure Apple Sign In, the application will run in simulation mode for Apple authentication.

## Running the Application

1. Install the required packages: `pip install -r requirements.txt`
2. Make sure your `.env` file is set up with the required credentials
3. Run the application: `python app.py`
4. Access the application at http://localhost:5000

## Features

- User authentication (email/password and social login)
- Career guidance and resources for polytechnic students
- College predictor
- Educational resources and curriculum information
- Job roadmaps and career planning tools

## Development Notes

### Reusable Components

#### Header/Navbar Component

The application uses a reusable header component for consistent navigation across all pages. This component includes:

1. PolytechEDGE branding
2. Navigation links to main sections
3. Light/dark mode toggle
4. User account dropdown (when logged in) or login/signup buttons (when not logged in)

To include the header in a template:

```html
{% include 'components/header.html' %}
```

Make sure the template passes the following variables:
- `is_logged_in`: Boolean indicating if a user is logged in
- `username`: The username of the logged-in user (only needed if `is_logged_in` is true)

### Authentication Flow

The application uses Flask's session management to maintain user login state. When a user attempts to access a protected route:

1. The route checks if the user is logged in using session data
2. If not logged in, the user is redirected to the login page
3. The original URL is stored in a `next` parameter
4. After successful login, the user is redirected to their originally requested page

### Theme Toggle

The application supports both light and dark themes, toggled via JavaScript:

```javascript
function toggleTheme() {
    const body = document.body;
    if (body.getAttribute('data-bs-theme') === 'dark') {
        body.setAttribute('data-bs-theme', 'light');
    } else {
        body.setAttribute('data-bs-theme', 'dark');
    }
}
```

## Setup and Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up the database: `python -c "from app import app, db; with app.app_context(): db.create_all()"`
4. Run the application: `python app.py`
5. Access the application at http://localhost:5000

## Contributors

- The PolytechEDGE Team 