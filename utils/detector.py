import re
import logging
from typing import Dict, List, Any, Tuple, Optional

# Set up logging
logger = logging.getLogger(__name__)

# Regular expression patterns for sensitive data
REGEX_PATTERNS = {
    "api_keys": {
        "stripe_key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
        "github_pat": r"gh[pousr]_[A-Za-z0-9_]{36,251}",
        "generic_api_key": r"[a-zA-Z0-9_\-]{20,40}"
    },
    "credentials": {
        "password": r"(?i)(?:password|passwd|pwd)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9!@#$%^&*()_\-+=<>?]{8,32})['\"]?",
        "ssh_key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "access_token": r"(?:access|auth|authentication)[\s\-_]*token[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-.~+/]{32,256})['\"]?"
    },
    "personal_info": {
        "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "us_phone": r"(?:(?:\+1|1)[\s\-]?)?(?:\(?[0-9]{3}\)?[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}|\([0-9]{3}\)[\s]?[0-9]{3}[\s\-][0-9]{4})",
        "us_ssn": r"(?<!\d)(?<!\()(?<!\+)(?<![\d-])(?<!\(\d{3}\)[\s])(?<![\d]{3}[\s\-])(?<![\d]{3}\))(?<![\d]{3}[\s])([0-9]{3}[\-][0-9]{2}[\-][0-9]{4}|[0-9]{3}[\s][0-9]{2}[\s][0-9]{4}|[0-9]{3}[0-9]{2}[0-9]{4})(?!\d)",
        "dob": r"(?:(?:19|20)[0-9]{2}[\-/\.][0-1][0-9][\-/\.][0-3][0-9])|(?:[0-1][0-9][\-/\.][0-3][0-9][\-/\.](?:19|20)[0-9]{2})"
    },
    "financial": {
        "credit_card": r"(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})",
        "bank_account": r"[0-9]{8,17}",
        "routing_number": r"[0-9]{9}"
    },
    "company_info": {
        "internal_project": r"(?i)(?:project|proj|initiative)[\s\-_]*(?:code|name)?[\s\-_]*:?[\s]*['\"]?([a-zA-Z0-9\-_]{3,30})['\"]?",
        "budget_info": r"(?i)(?:budget|revenue|forecast)[\s\-_]*:?[\s]*\$?[\s]*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?[MBKmk]?)",
        "sensitive_metric": r"(?i)(?:profit margin|market share|conversion rate)[\s\-_]*:?[\s]*([0-9]{1,2}(?:\.[0-9]{1,2})?\%?)"
    }
}

# Named entities for organization-specific terms
NAMED_ENTITIES = {
    "product_names": ["ProjectX", "SecureApp", "DataShield", "TechWave", "SmartSecurity"],
    "client_names": ["Acme Corp", "TechGiant", "GlobalFinance", "MegaSoft", "IndustrialSolutions"],
    "internal_systems": ["ATLAS", "ORION", "SENTINEL", "PHOENIX", "MERCURY"]
}

def detect_regex_pattern(text: str, pattern: str, pattern_name: str, 
                         category: str, sensitivity: str) -> List[Dict[str, Any]]:
    """
    Detect matches for a specific regex pattern in text
    
    Args:
        text: The text to analyze
        pattern: Regex pattern to search for
        pattern_name: Name of the pattern (e.g., 'credit_card')
        category: Category of sensitive data (e.g., 'financial')
        sensitivity: Severity level (low, medium, high)
    
    Returns:
        List of dictionaries containing detected items
    """
    results = []
    matches = re.finditer(pattern, text)
    
    for match in matches:
        # Get the matching value
        value = match.group(0)
        
        # Some patterns have the actual value in a capture group
        if len(match.groups()) > 0:
            value = match.group(1)
        
        results.append({
            "type": pattern_name.replace("_", " ").title(),
            "value": value,
            "position": {
                "start": match.start(),
                "end": match.end()
            },
            "severity": sensitivity
        })
    
    return results

def detect_named_entities(text: str, entities: List[str], entity_type: str, 
                          category: str, sensitivity: str) -> List[Dict[str, Any]]:
    """
    Detect named entities in text
    
    Args:
        text: The text to analyze
        entities: List of entity names to look for
        entity_type: Type of entity (e.g., 'product_names')
        category: Category of sensitive data
        sensitivity: Severity level (low, medium, high)
    
    Returns:
        List of dictionaries containing detected items
    """
    results = []
    
    for entity in entities:
        for match in re.finditer(r'\b' + re.escape(entity) + r'\b', text, re.IGNORECASE):
            results.append({
                "type": entity_type.replace("_", " ").title(),
                "value": match.group(0),
                "position": {
                    "start": match.start(),
                    "end": match.end()
                },
                "severity": sensitivity
            })
    
    return results

def detect_sensitive_data(text: str, config) -> Dict[str, Any]:
    """
    Main function to detect sensitive data in text based on configuration
    
    Args:
        text: The text to analyze
        config: Configuration object with detection settings
    
    Returns:
        Dictionary containing detection results and risk assessment
    """
    try:
        if not text:
            return {
                "detections": {},
                "risk_level": "Low",
                "recommendations": []
            }
        
        detections = {}
        all_detections = []
        recommendations = []
    except Exception as e:
        logger.error(f"Error initializing sensitive data detection: {str(e)}")
        return {
            "detections": {},
            "risk_level": "Error",
            "recommendations": ["An error occurred during analysis. Please try again."]
        }
    
    # Determine sensitivity thresholds based on configuration
    sensitivity_level = getattr(config, 'sensitivity_level', 2)  # Default to medium
    
    # Set up category mappings to configuration settings
    category_config_map = {
        "api_keys": getattr(config, 'scan_api_keys', True),
        "credentials": getattr(config, 'scan_passwords', True),
        "financial": getattr(config, 'scan_credit_cards', True),
        "personal_info": getattr(config, 'scan_personal_info', True),
        "company_info": getattr(config, 'scan_company_info', True)
    }
    
    # Process regex patterns based on configuration
    for category, patterns in REGEX_PATTERNS.items():
        # Skip categories that are disabled in config
        if not category_config_map.get(category, True):
            continue
        
        category_detections = []
        
        for pattern_name, pattern in patterns.items():
            # Determine severity based on pattern and sensitivity level
            severity = determine_severity(pattern_name, sensitivity_level)
            
            # Skip low severity patterns if sensitivity level is low
            if sensitivity_level == 1 and severity == "Low":
                continue
                
            # Detect pattern matches
            matches = detect_regex_pattern(text, pattern, pattern_name, category, severity)
            category_detections.extend(matches)
        
        if category_detections:
            detections[category] = category_detections
            all_detections.extend(category_detections)
    
    # Process named entities if company info scanning is enabled
    if category_config_map.get("company_info", True):
        company_detections = []
        
        for entity_type, entities in NAMED_ENTITIES.items():
            # Always treat named entities as medium severity
            severity = "Medium"
            
            # Skip low severity patterns if sensitivity level is low
            if sensitivity_level == 1 and severity == "Low":
                continue
                
            matches = detect_named_entities(text, entities, entity_type, "company_info", severity)
            company_detections.extend(matches)
        
        if company_detections:
            if "company_info" not in detections:
                detections["company_info"] = []
            detections["company_info"].extend(company_detections)
            all_detections.extend(company_detections)
    
    # Assess overall risk level
    risk_level = assess_risk_level(all_detections)
    
    # Generate recommendations
    recommendations = generate_recommendations(all_detections)
    
    return {
        "detections": detections,
        "risk_level": risk_level,
        "recommendations": recommendations
    }

def determine_severity(pattern_name: str, sensitivity_level: int) -> str:
    """
    Determine the severity of a detection based on pattern type and sensitivity level
    
    Args:
        pattern_name: Name of the pattern
        sensitivity_level: Configured sensitivity level (1=low, 2=medium, 3=high)
    
    Returns:
        Severity string (Low, Medium, High)
    """
    # High severity patterns regardless of sensitivity level
    high_severity_patterns = ["ssh_key", "aws_key", "credit_card", "us_ssn", "stripe_key"]
    
    # Medium severity patterns
    medium_severity_patterns = ["password", "access_token", "budget_info", 
                               "email", "us_phone", "dob"]
    
    if pattern_name in high_severity_patterns:
        return "High"
    elif pattern_name in medium_severity_patterns:
        return "Medium" if sensitivity_level >= 2 else "Low"
    else:
        # For other patterns, use sensitivity level to determine severity
        if sensitivity_level == 3:
            return "Medium"
        else:
            return "Low"

def assess_risk_level(detections: List[Dict[str, Any]]) -> str:
    """
    Assess overall risk level based on detected items
    
    Args:
        detections: List of detected sensitive items
    
    Returns:
        Risk level string (Low, Medium, High)
    """
    if not detections:
        return "Low"
    
    high_count = sum(1 for d in detections if d["severity"] == "High")
    medium_count = sum(1 for d in detections if d["severity"] == "Medium")
    
    if high_count >= 1:
        return "High"
    elif medium_count >= 2:
        return "Medium"
    elif medium_count >= 1 or len(detections) >= 3:
        return "Medium"
    else:
        return "Low"

def generate_recommendations(detections: List[Dict[str, Any]]) -> List[str]:
    """
    Generate recommendations based on detected sensitive data
    
    Args:
        detections: List of detected sensitive items
    
    Returns:
        List of recommendation strings
    """
    recommendations = []
    
    if not detections:
        return recommendations
    
    # Count detections by type
    detection_types = {}
    for detection in detections:
        detection_type = detection["type"].lower()
        detection_types[detection_type] = detection_types.get(detection_type, 0) + 1
    
    # Generate specific recommendations
    if any(k in detection_types for k in ["api key", "stripe key", "aws key", "google api"]):
        recommendations.append("Consider removing API keys and using environment variables instead.")
    
    if "password" in detection_types:
        recommendations.append("Avoid sharing passwords. Use a password manager or secure communication channel.")
    
    if any(k in detection_types for k in ["credit card", "bank account", "routing number"]):
        recommendations.append("Financial information detected. Never share financial details with AI tools.")
    
    if any(k in detection_types for k in ["email", "us phone", "ssn", "dob"]):
        recommendations.append("Personal information detected. Consider anonymizing or removing this data.")
    
    if any(k in detection_types for k in ["product names", "client names", "internal systems"]):
        recommendations.append("Company-specific information detected. Consider using generic terms instead.")
    
    # Add general recommendation if we have high severity items
    has_high_severity = any(d["severity"] == "High" for d in detections)
    if has_high_severity:
        recommendations.append("High-risk information detected. Review and remove sensitive data before sending.")
    
    return recommendations
