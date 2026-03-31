import json

RISK_MAP = {
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'informational': 'Info',
    'info': 'Info',
}

def normalize_risk(riskdesc: str) -> str:
    """Normalize risk level string from ZAP output to a clean label."""
    if not riskdesc:
        return 'Info'
    # riskdesc format: "High (3)" or "Medium (2)" etc.
    level = riskdesc.split('(')[0].strip().lower()
    return RISK_MAP.get(level, 'Info')

def strip_html(text: str) -> str:
    """Remove basic HTML tags from ZAP description/solution fields."""
    import re
    if not text:
        return ''
    clean = re.sub(r'<[^>]+>', ' ', text)
    return ' '.join(clean.split())

def parse_zap(file_path: str) -> list[dict]:
    """
    Parse a ZAP JSON report and return a list of vulnerability dicts.

    Args:
        file_path: Path to the ZAP JSON export file.

    Returns:
        List of dicts with keys: name, risk_level, description, solution
    
    Raises:
        ValueError: If the file is not valid ZAP JSON format.
        FileNotFoundError: If the file does not exist.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"ZAP report not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON file: {e}")

    if 'site' not in data or not data['site']:
        raise ValueError("Invalid ZAP report: missing 'site' key or empty site list.")

    vulnerabilities = []

    for site in data['site']:
        alerts = site.get('alerts', [])
        for alert in alerts:
            name = alert.get('alert', 'Unknown Vulnerability')
            riskdesc = alert.get('riskdesc', '')
            description = strip_html(alert.get('desc', ''))
            solution = strip_html(alert.get('solution', ''))

            vulnerabilities.append({
                'vuln_name': name,
                'risk_level': normalize_risk(riskdesc),
                'description': description,
                'solution': solution,
                'status': 'Open',
            })

    return vulnerabilities
