# AI Safeguard: Sensitive Data Protection Tool

AI Safeguard is a comprehensive tool that helps protect your sensitive data from being accidentally shared with AI tools like ChatGPT. The application analyzes text input before it's sent to AI services, identifies potentially sensitive information, and provides warnings or blocks based on configurable security policies.

## Features

- **Pattern-based Detection**: Identify API keys, passwords, credit cards, and other structured sensitive data with advanced pattern matching
- **NLP Classification**: Use natural language processing to detect confidential content and context-specific information
- **Named Entity Recognition**: Identify organization-specific terms that could expose sensitive information
- **Real-time Analysis**: Get instant feedback on potential data exposure risks
- **Highlighting**: Visualize detected sensitive information with clear highlighting
- **Configuration Options**: Customize detection settings and sensitivity thresholds
- **Recommendations**: Receive actionable suggestions to reduce exposure risk

## Getting Started

### Prerequisites

- Python 3.8+
- Flask
- NLTK
- spaCy
- PostgreSQL

### Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up environment variables for database connection:
   - `DATABASE_URL`
   - `SESSION_SECRET`
4. Run the application: `python main.py`

### Usage

1. Visit the homepage at `http://localhost:5000`
2. Enter or paste text in the text analysis area
3. Click "Analyze Text" to detect sensitive information
4. Review the analysis results and follow recommendations
5. Create an account to access additional features:
   - Custom configurations
   - Scan history
   - Detailed analytics

## Configuration Options

AI Safeguard offers several ways to customize detection:

- **Sensitivity Level**: Choose between Low, Medium, and High sensitivity
- **Detection Categories**: Enable/disable specific types of detection
- **Custom Definitions**: (Coming soon) Define your own patterns and entities

## Security Considerations

- AI Safeguard runs locally and does not share your text with external services
- Detected sensitive information is never stored in plain text
- All communications are encrypted using HTTPS
- User passwords are securely hashed

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NLTK for natural language processing
- spaCy for named entity recognition
- Flask for the web framework
- PostgreSQL for secure data storage
