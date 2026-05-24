# loading the important libraries

import re
import json
from pathlib import Path
import os


# Step 1 loading the input file


# opeun the input file and read its content
with open("input/raw-text.txt", "r", encoding="utf-8") as file:
    text = file.read()


# Main regex patterns for data extraction


# Regex patterns for  email

email_pattern = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
)


# ALU - specific email Regex patterns

alu_official_pattern = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@alueducation\.com\b'
)
alu_alumni_pattern = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com\b'
)
alu_si_pattern = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@si\.alueducation\.com\b'
)

# Regex for Credit Card Numbers

credit_card_pattern = re.compile(
    r'\b(?:\d{4}[- ]?){3}\d{4}\b'
)

#Regex for Phone Numbers

phone_pattern = re.compile(
    r'\b(?:\+\d{1,3}[- ]?)?(?:\(?\d{2,4}\)?[- ]?)?\d{3}[- ]\d{3}[- ]\d{3,4}\b'
)


# Regex for URLs

url_pattern = re.compile(
    r'https?://[^\s"<>()]+'
)


# Regex for Hashtags

hashtag_pattern = re.compile(
    r'#\w+'
)


# Regex for Currency Amounts (USD, EUR, RWF, GBP)

currency_pattern = re.compile(
    r'(?:\$|EUR\s|RWF\s|£)\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
)


# SECURITY / HOSTILE INPUT DETECTION
# This is testing for malicious patterns such as sql injections and xss attempts

malicious_patterns = {
    "xss_attempts": [
        r'<script.*?>.*?</script>',
        r'<img.*?onerror=.*?>',
        r'<svg.*?onload=.*?>',
        r'<iframe.*?>.*?</iframe>'
    ],

    "sql_injection_attempts": [
        r'DROP\s+TABLE',
        r'SELECT\s+\*',
        r'UNION\s+SELECT',
        r"' OR '1'='1",
        r"admin'\s*--"
    ],

    "command_injection_attempts": [
        r'rm\s+-rf\s+/',
        r'sudo\s+reboot',
        r'shutdown',
        r'cat\s+/etc/passwd'
    ]
}


# extract matches based on the provided regex pattern and return unique values


def extract_matches(pattern, content):
    matches = []

    for match in pattern.finditer(content):
        value = match.group().strip()

        if value not in matches:
            matches.append(value)

    return matches

# Performing extraction of valid data based on the defined regex patterns


emails = extract_matches(email_pattern, text)

alu_official_emails = extract_matches(alu_official_pattern, text)

alu_alumni_emails = extract_matches(alu_alumni_pattern, text)

alu_si_emails = extract_matches(alu_si_pattern, text)

urls = extract_matches(url_pattern, text)

phone_numbers = extract_matches(phone_pattern, text)

hashtags = list(set(
    tag.lower()
    for tag in extract_matches(hashtag_pattern, text)
))

currency_amounts = extract_matches(currency_pattern, text)

credit_cards_raw = extract_matches(credit_card_pattern, text)


# masking credit card numbers


masked_credit_cards = []

for card in credit_cards_raw:
    cleaned = re.sub(r'[- ]', '', card)

    # Mask all except last 4 digits
    masked = '*' * (len(cleaned) - 4) + cleaned[-4:]

    masked_credit_cards.append(masked)


# Perform security analysis by checking for malicious patterns in the text


security_findings = {}

for category, patterns in malicious_patterns.items():

    findings = []

    for pattern in patterns:

        matches = re.findall(pattern, text, re.IGNORECASE)

        findings.extend(matches)

    security_findings[category] = findings


# Regex for Invalid or Malformed Entries


invalid_email_pattern = re.compile(
    r'\b(?:[^\s@]+@@[^\s@]+|[^\s@]+@\.[^\s@]+|[^\s@]+@|@[^\s@]+|[^\s@]+\.\.[a-zA-Z]+)\b'
)

invalid_credit_card_pattern = re.compile(
    r'\b(?:\d{4}-[A-Z]{4}-\d{4}-[A-Z]{4}|\d{4}-\d{4}-\d{4}(?!-\d{4})|\d{17,})\b'
)

invalid_phone_pattern = re.compile(
    r'\b(?:123|000-000-000|\+\+250\d+)\b'
)

invalid_url_pattern = re.compile(
    r'\b(?:htp://\S+|https//\S+|http:///+\S+|www\.[^\s]+)\b'
)

invalid_entries = {
    "invalid_emails": extract_matches(invalid_email_pattern, text),
    "invalid_credit_cards": extract_matches(invalid_credit_card_pattern, text),
    "invalid_phone_numbers": extract_matches(invalid_phone_pattern, text),
    "invalid_urls": extract_matches(invalid_url_pattern, text)
}


# Getting the output ready in a structured format


results = {

    "summary": {
        "total_valid_emails": len(emails),
        "total_alu_official_emails": len(alu_official_emails),
        "total_alu_alumni_emails": len(alu_alumni_emails),
        "total_alu_si_emails": len(alu_si_emails),
        "total_credit_cards": len(masked_credit_cards),
        "total_phone_numbers": len(phone_numbers),
        "total_urls": len(urls),
        "total_hashtags": len(hashtags),
        "total_currency_amounts": len(currency_amounts)
    },

    "valid_data": {

        "emails": emails,

        "alu_specific_emails": {
            "official": alu_official_emails,
            "alumni": alu_alumni_emails,
            "si": alu_si_emails
        },

        "credit_cards_masked": masked_credit_cards,

        "phone_numbers": phone_numbers,

        "urls": urls,

        "hashtags": hashtags,

        "currency_amounts": currency_amounts
    },

    "security_analysis": {

        "malicious_content_detected": security_findings,

        "invalid_or_malformed_entries": invalid_entries
    }
}


# Save output to JSON file


output_path = Path("../output/sample-output.json")

with open("output/sample-output.json", "w", encoding="utf-8") as outfile:
    json.dump(results, outfile, indent=4)


# Log output to console


print("=" * 60)
print("REGEX EXTRACTION & SECURITY ANALYSIS COMPLETE")
print("=" * 60)

print("\nVALID EMAILS FOUND:")
for email in emails:
    print("-", email)

print("\nMASKED CREDIT CARDS:")
for card in masked_credit_cards:
    print("-", card)

print("\nSECURITY WARNINGS DETECTED:")
for category, findings in security_findings.items():
    print(f"\n{category.upper()}:")
    for finding in findings:
        print("-", finding)

print("\nResults saved to:")
print(output_path)

print("\nPROGRAM FINISHED SUCCESSFULLY")