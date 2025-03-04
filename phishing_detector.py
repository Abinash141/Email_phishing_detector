import requests
from bs4 import BeautifulSoup
import re

def check_suspicious_url(url):
    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'banking', 'paypal']
    for keyword in suspicious_keywords:
        if keyword in url:
            return True
    return False

def analyze_email_headers(headers):
    if 'from' in headers and 'reply-to' in headers:
        if headers['from'] != headers['reply-to']:
            return True
    return False

def check_phishing_database(url):
    try:
        response = requests.get("https://openphish.com/feed.txt")
        if url in response.text:
            return True
    except:
        pass
    return False

def detect_phishing(email_content, url):
    if check_suspicious_url(url):
        print("Suspicious URL detected.")
        return True

    if analyze_email_headers(email_content):
        print("Email header spoofing detected.")
        return True

    if check_phishing_database(url):
        print("URL found in phishing database.")
        return True

    print("No phishing detected.")
    return False

def get_user_input():
    print("Enter email details:")
    from_email = input("From: ")
    reply_to_email = input("Reply-To: ")
    url = input("Enter the URL to check: ")

    email_content = {
        'from': from_email,
        'reply-to': reply_to_email
    }

    return email_content, url

if __name__ == "__main__":
    email_content, url = get_user_input()
    detect_phishing(email_content, url)