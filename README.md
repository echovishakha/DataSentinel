# AI Safeguard: Sensitive Data Protection Tool

![AI Safeguard Logo](https://i.imgur.com/jKNKnC3.png)

AI Safeguard is a comprehensive tool that helps protect your sensitive data from being accidentally shared with AI tools like ChatGPT, Claude, and other large language models. The application analyzes text input before it's sent to AI services, identifies potentially sensitive information, and provides warnings or blocks based on configurable security policies.

**🔗 [Try AI Safeguard Now](https://aisafeguard.replit.app)** 

## 📸 Screenshots

### Dashboard View
![Dashboard Screenshot](https://i.imgur.com/pL6f4Rx.png)
*The dashboard provides a comprehensive view of text analysis and configuration settings.*

### Analysis Results
![Analysis Results](https://i.imgur.com/K8vY9Vj.png)
*Results screen showing detected sensitive information with color-coded risk levels.*

### Configuration Management
![Configuration Management](https://i.imgur.com/bTm4Sdp.png)
*Users can create and manage multiple detection configurations with custom settings.*

## ✨ Key Features

- **Pattern-based Detection**: Identify API keys, passwords, credit cards, and other structured sensitive data with advanced pattern matching
- **NLP Classification**: Use natural language processing to detect confidential content and context-specific information
- **Named Entity Recognition**: Identify organization-specific terms that could expose sensitive information
- **Sensitive Personal Information Detection**: Recognize and protect personal attributes like gender identity, pronouns, religion, and ethnicity
- **Real-time Analysis**: Get instant feedback on potential data exposure risks
- **Intelligent Highlighting**: Visualize detected sensitive information with clear, context-aware highlighting
- **Custom Configuration Options**: Tailor detection settings and sensitivity thresholds to your needs
- **Smart Recommendations**: Receive actionable suggestions to reduce exposure risk
- **Scan History**: Keep track of previous analyses and monitor sensitive data trends

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Flask and Flask extensions
- NLTK for natural language processing
- PostgreSQL database
- Modern web browser

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ai-safeguard.git
   cd ai-safeguard
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```
   export DATABASE_URL="postgresql://username:password@localhost/safeguard"
   export SESSION_SECRET="your-secure-session-secret"
   ```

4. Initialize the database:
   ```
   flask db init
   flask db migrate
   flask db upgrade
   ```

5. Run the application:
   ```
   gunicorn --bind 0.0.0.0:5000 main:app
   ```

### Quick Start Guide

1. **Open the application** in your web browser
2. **Enter or paste text** in the analysis area
3. **Click "Analyze Text"** to detect sensitive information
4. **Review the results** showing highlighted sensitive data
5. **Follow recommendations** to secure your information
6. Use the **"Clear Text"** button to reset the input area for new text

## 🔍 Detection Capabilities

AI Safeguard can detect a wide range of sensitive information:

| Category | Examples |
|----------|----------|
| API Keys | Stripe, AWS, Google, GitHub tokens, generic API keys |
| Credentials | Passwords, SSH keys, access tokens |
| Personal Info | Email addresses, phone numbers, SSNs, dates of birth |
| Sensitive Personal Attributes | Gender identity, pronouns, religion, ethnicity, sexual orientation |
| Financial Data | Credit card numbers, bank accounts, routing numbers |
| Company Information | Internal project names, budget info, performance metrics |

## ⚙️ Configuration Options

AI Safeguard offers several ways to customize detection:

### Sensitivity Levels
- **Low**: Only detect obvious sensitive data with minimal false positives
- **Medium**: Balanced detection with moderate sensitivity
- **High**: Aggressive detection that may include more false positives

### Detection Categories
Enable or disable specific types of detection:
- API Keys
- Passwords
- Credit Cards
- Personal Information
- Company Information

### Coming Soon
- Custom pattern definitions
- Organization-specific terminology detection
- API integration options

## 🔒 Security Considerations

- AI Safeguard employs a defense-in-depth approach to security
- All detected sensitive information is processed locally in memory
- Scan history stores only truncated samples of analyzed text
- All database content is properly sanitized
- User passwords are securely hashed using Werkzeug's security features
- Session management uses secure cookies

## 💻 Technical Details

### Architecture
- **Frontend**: HTML5, CSS3 (Bootstrap), JavaScript
- **Backend**: Python 3.11, Flask web framework
- **Database**: PostgreSQL
- **NLP**: NLTK for text processing and classification
- **Hosting**: Deployed on Replit infrastructure

### Code Organization
- `app.py` - Main application setup and routing
- `models.py` - Database models and relationships
- `utils/detector.py` - Sensitive data detection logic
- `utils/classifier.py` - Text classification using NLP
- `static/js/main.js` - Frontend interaction logic
- `templates/` - HTML templates for the UI

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- NLTK for natural language processing capabilities
- Flask for the lightweight and flexible web framework
- PostgreSQL for secure and reliable data storage
- Bootstrap for responsive UI components
- The open-source community for inspiration and resources

---

*AI Safeguard - Protecting Your Sensitive Information in the Age of AI*
