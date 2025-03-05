# HR-Map Application

A web application for HR mapping and resource management.

## Deployment Instructions

### Prerequisites
- GitHub account
- Vercel account
- Neon PostgreSQL database

### Setting Up the Database
1. Create a Neon PostgreSQL database
2. Make sure to select an EU region for GDPR compliance
3. Get your database connection string

### Deploying to Vercel
1. Push your code to GitHub
2. Import your repository in Vercel
3. Set up the following environment variables in Vercel:
   - `DATABASE_URL`: Your Neon PostgreSQL connection string
   - `SECRET_KEY`: A secure random string for session management

### Database Initialization
After deployment, you'll need to initialize your database schema:
1. Use Neon's SQL editor to connect to your database
2. Run the contents of `schema.sql` to create the necessary tables

## Local Development

### Environment Variables
Create a `.env` file in the root directory with the following variables:
```
DATABASE_URL=your_database_connection_string
SECRET_KEY=your_secret_key
DEBUG=True
```

### Running Locally
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## Security Notes
- Never commit `.env` files or any files containing credentials
- Always use environment variables for sensitive information
- The application is configured to use HTTPS and secure cookies

## GDPR Compliance
- Data is stored in EU regions
- Database encryption is enabled
- User data is handled according to GDPR requirements 