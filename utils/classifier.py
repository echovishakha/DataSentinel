import re
import logging
from typing import Dict, List, Any, Tuple, Optional
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from collections import Counter

# Set up logging
logger = logging.getLogger(__name__)

# Download required NLTK resources (only run once when app initializes)
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
    logger.info("NLTK resources already downloaded")
except LookupError as e:
    logger.warning(f"NLTK resources not found: {e}")
    try:
        logger.info("Downloading NLTK resources...")
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        logger.info("NLTK resources downloaded successfully")
    except Exception as download_error:
        logger.error(f"Failed to download NLTK resources: {download_error}")

# Define fallback stop words in case NLTK fails
FALLBACK_STOPWORDS = set([
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', 
    'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his', 'himself', 
    'she', 'her', 'hers', 'herself', 'it', 'its', 'itself', 'they', 'them', 
    'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom', 'this', 
    'that', 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been', 
    'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 
    'a', 'an', 'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until', 
    'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against', 'between', 
    'into', 'through', 'during', 'before', 'after', 'above', 'below', 'to', 
    'from', 'up', 'down', 'in', 'out', 'on', 'off', 'over', 'under', 'again', 
    'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 
    'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 
    'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 
    'very', 's', 't', 'can', 'will', 'just', 'don', 'should', 'now'
])
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

# Define confidential content keyword dictionaries
CONFIDENTIAL_KEYWORDS = {
    "financial": [
        "revenue", "profit", "loss", "margin", "budget", "forecast", "investment", 
        "quarterly", "earnings", "fiscal", "dividend", "shareholder", "financial", 
        "balance sheet", "income statement", "cash flow", "assets", "liabilities",
        "stock", "shares", "equity", "bond", "portfolio", "hedge", "fund", "merger",
        "acquisition", "bankruptcy", "liquidity", "capital", "expense", "depreciation",
        "amortization", "ebitda", "p/e ratio", "valuation", "underperforming", "overperforming"
    ],
    
    "personal": [
        "name", "address", "phone", "email", "birth", "ssn", "social security", "passport",
        "license", "identity", "id number", "credential", "username", "login", "health",
        "medical", "diagnosis", "prescription", "medication", "illness", "condition",
        "patient", "doctor", "hospital", "clinic", "insurance", "family", "spouse",
        "child", "parent", "relative", "marital", "status", "religion", "political", "sexual"
    ],
    
    "corporate": [
        "confidential", "classified", "internal", "private", "sensitive", "restricted",
        "proprietary", "secret", "nda", "non-disclosure", "intellectual property", "ip",
        "trademark", "copyright", "patent", "trade secret", "competitive", "competitor",
        "strategy", "strategic", "initiative", "roadmap", "launch", "unreleased", "upcoming",
        "prototype", "beta", "test", "r&d", "research", "development", "acquisition",
        "merger", "restructure", "reorganization", "layoff", "termination", "lawsuit",
        "litigation", "legal", "compliance", "audit", "investigation", "board", "executive"
    ],
    
    "technical": [
        "password", "credential", "authentication", "authorization", "token", "key", "secret",
        "api", "algorithm", "source code", "architecture", "infrastructure", "server",
        "database", "schema", "backend", "frontend", "endpoint", "encryption", "decrypt",
        "hash", "salt", "cipher", "vpn", "firewall", "security", "vulnerability", "exploit",
        "breach", "hack", "backdoor", "zero-day", "bug", "patch", "update", "version",
        "protocol", "certificate", "private key", "ssh", "tls", "ssl", "config", "configuration"
    ]
}

# Define confidence thresholds for each category
CONFIDENCE_THRESHOLDS = {
    "financial": 0.15,
    "personal": 0.15,
    "corporate": 0.15,
    "technical": 0.15
}

def preprocess_text(text: str) -> List[str]:
    """
    Preprocess text for classification
    
    Args:
        text: The input text to preprocess
    
    Returns:
        List of processed tokens
    """
    # Convert to lowercase
    text = text.lower()
    
    # Custom simple tokenization as a fallback method in case NLTK has issues
    try:
        # Try using NLTK tokenizer
        tokens = word_tokenize(text)
    except:
        # Fallback to simple tokenization
        tokens = re.findall(r'\b\w+\b', text)
    
    # Remove stopwords and non-alphabetic tokens
    try:
        stop_words = set(stopwords.words('english'))
    except:
        # Fallback to a minimal list of common stopwords
        stop_words = {'a', 'an', 'the', 'and', 'or', 'but', 'is', 'are', 'was', 'were', 
                     'be', 'been', 'being', 'in', 'on', 'at', 'to', 'for', 'with'}
    
    tokens = [token for token in tokens if token.isalpha() and token not in stop_words]
    
    return tokens

def classify_text(text: str) -> Dict[str, float]:
    """
    Classify text into confidentiality categories
    
    Args:
        text: The text to classify
    
    Returns:
        Dictionary with category names and confidence scores
    """
    if not text:
        return {}
    
    # Preprocess text
    tokens = preprocess_text(text)
    if not tokens:
        return {}
    
    # Count the total tokens for calculating percentages
    total_tokens = len(tokens)
    
    # Define N-grams to check (1-gram and 2-gram)
    unigrams = tokens
    bigrams = [' '.join(tokens[i:i+2]) for i in range(len(tokens)-1)]
    
    # Combine N-grams for matching
    all_terms = unigrams + bigrams
    
    # Count matches for each category
    category_matches = {}
    
    for category, keywords in CONFIDENTIAL_KEYWORDS.items():
        # Create a set of keywords for faster lookup
        keyword_set = set(keywords)
        
        # Count matches
        matches = sum(1 for term in all_terms if term in keyword_set)
        
        # Calculate confidence score as percentage of matching tokens
        # Add weighting factor for longer texts
        confidence = min(1.0, matches / (total_tokens + 10) * 2)
        
        # Apply threshold
        if confidence >= CONFIDENCE_THRESHOLDS[category]:
            category_matches[category] = confidence
    
    # Check for high concentrations of specific keywords
    term_counter = Counter(all_terms)
    for term, count in term_counter.items():
        # If a term appears frequently (more than 2% of text), check if it's sensitive
        term_ratio = count / total_tokens
        if term_ratio > 0.02:
            for category, keywords in CONFIDENTIAL_KEYWORDS.items():
                if term in keywords:
                    # Boost confidence for this category
                    current_confidence = category_matches.get(category, 0)
                    category_matches[category] = min(1.0, current_confidence + term_ratio * 2)
    
    # Analyze text length and structure for additional signals
    analyze_structure_result = analyze_text_structure(text)
    for category, confidence_boost in analyze_structure_result.items():
        if category in category_matches:
            category_matches[category] = min(1.0, category_matches[category] + confidence_boost)
        elif confidence_boost >= CONFIDENCE_THRESHOLDS[category]:
            category_matches[category] = confidence_boost
    
    return category_matches

def analyze_text_structure(text: str) -> Dict[str, float]:
    """
    Analyze text structure for additional classification signals
    
    Args:
        text: The text to analyze
    
    Returns:
        Dictionary with category boosts
    """
    confidence_boosts = {}
    
    # Check for structured financial data
    if re.search(r'\$\s*\d+(?:[,.]\d+)?(?:\s*[kmbt])?', text, re.IGNORECASE):
        confidence_boosts["financial"] = 0.2
    
    # Check for table-like structures with numbers (often financial or technical data)
    if re.search(r'(\|\s*\w+\s*\|.*\|\s*\d+\s*\|)|(\+[-+]+\+)', text):
        confidence_boosts["financial"] = confidence_boosts.get("financial", 0) + 0.15
        confidence_boosts["technical"] = 0.15
    
    # Check for email-like format (often contains sensitive info)
    if re.search(r'^(from|to|subject):', text, re.IGNORECASE) or re.search(r'^\s*>.*\n', text):
        confidence_boosts["corporate"] = 0.1
        confidence_boosts["personal"] = 0.1
    
    # Check for bullet points with sensitive-looking content
    bullet_points = re.findall(r'(?:^|\n)(?:\*|-|\d+\.)\s+(.+)(?:\n|$)', text)
    if len(bullet_points) > 2:
        confidence_boosts["corporate"] = confidence_boosts.get("corporate", 0) + 0.05
    
    # Check for JSON/XML/code-like syntax (often technical)
    if re.search(r'[{}\[\]<>][\s\w"\']*[:=]', text):
        confidence_boosts["technical"] = confidence_boosts.get("technical", 0) + 0.2
    
    # Check for personally identifiable format patterns
    if re.search(r'(?i)(?:name|email|phone|address|ssn|dob)[\s]*:[\s]*\w+', text):
        confidence_boosts["personal"] = confidence_boosts.get("personal", 0) + 0.25
    
    return confidence_boosts
