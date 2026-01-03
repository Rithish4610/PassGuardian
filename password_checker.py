# 🛡️ PASSGUARDIAN - Advanced Password Security Tool
# Innovative features: Breach detection, entropy analysis, passphrase generator, 
# pattern detection, estimated crack time, and secure password generation

import re
import hashlib
import secrets
import string
import math
import urllib.request
import urllib.error
import json
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════════════
# COMMON PASSWORDS & PATTERNS DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

COMMON_PASSWORDS = {
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', 'letmein', 'login', 'princess', 'admin', 'welcome', 'sunshine',
    'password1', 'password123', 'iloveyou', '1234567890', 'football', 'baseball'
}

KEYBOARD_PATTERNS = [
    'qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl', '123456789',
    '987654321', 'qazwsx', 'qazedc', '1qaz2wsx', 'abcdef', 'abcdefgh'
]

LEET_SPEAK_MAP = {'4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't'}

# Word list for passphrase generation
WORD_LIST = [
    'apple', 'banana', 'cherry', 'dragon', 'eagle', 'falcon', 'guitar', 'hammer',
    'island', 'jungle', 'kettle', 'lemon', 'mountain', 'nebula', 'ocean', 'piano',
    'quartz', 'river', 'sunset', 'thunder', 'umbrella', 'violet', 'whisper', 'xenon',
    'yellow', 'zephyr', 'anchor', 'breeze', 'castle', 'diamond', 'ember', 'forest',
    'glacier', 'horizon', 'impulse', 'jasmine', 'kingdom', 'lantern', 'meadow', 'nova',
    'orchid', 'phoenix', 'quantum', 'rainbow', 'sapphire', 'twilight', 'unity', 'venture',
    'wizard', 'crystal', 'cosmic', 'stellar', 'thunder', 'voyage', 'winter', 'zenith'
]

# ═══════════════════════════════════════════════════════════════════════════════
# INNOVATIVE FEATURE 1: HAVE I BEEN PWNED API INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

def check_breach_database(password):
    """
    Check if password has been exposed in data breaches using Have I Been Pwned API.
    Uses k-anonymity model - only first 5 chars of SHA1 hash are sent.
    """
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        request = urllib.request.Request(url, headers={'User-Agent': 'PassGuardian-PasswordChecker'})
        
        with urllib.request.urlopen(request, timeout=5) as response:
            hash_list = response.read().decode('utf-8')
            
        for line in hash_list.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return True, int(count)
        
        return False, 0
    except (urllib.error.URLError, Exception):
        return None, 0  # API unavailable

# ═══════════════════════════════════════════════════════════════════════════════
# INNOVATIVE FEATURE 2: ENTROPY & CRACK TIME CALCULATION
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_entropy(password):
    """Calculate password entropy in bits - measures true randomness."""
    charset_size = 0
    
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
        charset_size += 32
    
    if charset_size == 0:
        return 0
    
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def estimate_crack_time(password):
    """Estimate time to crack password with different attack methods."""
    entropy = calculate_entropy(password)
    
    # Guesses per second for different scenarios
    scenarios = {
        'online_throttled': 100,           # Online attack with rate limiting
        'online_unthrottled': 10_000,      # Online attack without limits
        'offline_slow': 10_000_000,        # Offline with slow hash (bcrypt)
        'offline_fast': 10_000_000_000,    # Offline with fast hash (MD5)
    }
    
    total_combinations = 2 ** entropy
    times = {}
    
    for scenario, guesses_per_sec in scenarios.items():
        seconds = total_combinations / (2 * guesses_per_sec)  # Average case
        times[scenario] = format_time(seconds)
    
    return times, entropy

def format_time(seconds):
    """Convert seconds to human-readable time format."""
    if seconds < 1:
        return "Instant ⚡"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds/86400)} days"
    elif seconds < 31536000 * 100:
        return f"{int(seconds/31536000)} years"
    elif seconds < 31536000 * 1000000:
        return f"{int(seconds/(31536000*1000)):,} thousand years"
    elif seconds < 31536000 * 1000000000:
        return f"{int(seconds/(31536000*1000000)):,} million years"
    else:
        return "Centuries+ 🏰"

# ═══════════════════════════════════════════════════════════════════════════════
# INNOVATIVE FEATURE 3: PATTERN & VULNERABILITY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_patterns(password):
    """Detect common patterns and vulnerabilities in passwords."""
    vulnerabilities = []
    password_lower = password.lower()
    
    # Check for common passwords
    if password_lower in COMMON_PASSWORDS:
        vulnerabilities.append(("🚫 CRITICAL", "This is a commonly used password - extremely easy to crack"))
    
    # Check for keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            vulnerabilities.append(("⚠️  WARNING", f"Contains keyboard pattern '{pattern}'"))
            break
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        vulnerabilities.append(("⚠️  WARNING", "Contains repeated characters (e.g., 'aaa')"))
    
    # Check for sequential numbers
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        vulnerabilities.append(("⚠️  WARNING", "Contains sequential numbers"))
    
    # Check for sequential letters
    if re.search(r'(abc|bcd|cde|def|efg|xyz)', password_lower):
        vulnerabilities.append(("⚠️  WARNING", "Contains sequential letters"))
    
    # Check for date patterns (years)
    if re.search(r'(19|20)\d{2}', password):
        vulnerabilities.append(("⚠️  WARNING", "Contains what looks like a year - easily guessable"))
    
    # Check for leet speak substitutions of common words
    decoded = password_lower
    for leet, char in LEET_SPEAK_MAP.items():
        decoded = decoded.replace(leet, char)
    if decoded in COMMON_PASSWORDS:
        vulnerabilities.append(("🚫 CRITICAL", "Leet-speak version of a common password"))
    
    # Check for personal info patterns
    if re.search(r'(password|pass|pwd|admin|user|login|welcome)', password_lower):
        vulnerabilities.append(("🚫 CRITICAL", "Contains common password-related words"))
    
    return vulnerabilities

# ═══════════════════════════════════════════════════════════════════════════════
# INNOVATIVE FEATURE 4: SECURE PASSWORD GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def generate_secure_password(length=16, include_symbols=True):
    """Generate a cryptographically secure random password."""
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        # Ensure it meets all criteria
        if (re.search(r'[a-z]', password) and
            re.search(r'[A-Z]', password) and
            re.search(r'[0-9]', password) and
            (not include_symbols or re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))):
            return password

def generate_passphrase(num_words=4, separator='-', capitalize=True):
    """Generate a memorable passphrase using random words."""
    words = [secrets.choice(WORD_LIST) for _ in range(num_words)]
    if capitalize:
        words = [word.capitalize() for word in words]
    
    # Add a random number for extra security
    passphrase = separator.join(words) + separator + str(secrets.randbelow(100))
    return passphrase

# ═══════════════════════════════════════════════════════════════════════════════
# INNOVATIVE FEATURE 5: PASSWORD STRENGTH VISUALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def create_strength_bar(score, max_score=10):
    """Create a visual strength bar."""
    filled = int((score / max_score) * 20)
    empty = 20 - filled
    
    if score >= 8:
        color = "\033[92m"  # Green
    elif score >= 6:
        color = "\033[94m"  # Blue
    elif score >= 4:
        color = "\033[93m"  # Yellow
    else:
        color = "\033[91m"  # Red
    
    bar = f"{color}{'█' * filled}{'░' * empty}\033[0m"
    return bar

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN PASSWORD ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def check_password_strength(password):
    """Comprehensive password strength analysis."""
    score = 0
    feedback = []
    bonuses = []
    
    # Basic checks (5 points max)
    if len(password) >= 8:
        score += 1
        if len(password) >= 12:
            score += 1
            bonuses.append("✅ Good length (12+ chars)")
        if len(password) >= 16:
            score += 1
            bonuses.append("✅ Excellent length (16+ chars)")
    else:
        feedback.append("❌ Password should be at least 8 characters long")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one UPPERCASE letter")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one lowercase letter")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9)")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one special character (!@#$% etc.)")
    
    # Bonus for variety
    unique_chars = len(set(password))
    if unique_chars >= len(password) * 0.7:
        score += 1
        bonuses.append("✅ Good character variety")
    
    # Penalty for patterns
    vulnerabilities = detect_patterns(password)
    for severity, _ in vulnerabilities:
        if "CRITICAL" in severity:
            score = max(0, score - 3)
        elif "WARNING" in severity:
            score = max(0, score - 1)
    
    # Cap score at 10
    score = min(score, 10)
    
    # Determine strength level
    if score >= 9:
        strength = "🏆 EXCEPTIONAL"
        color = "\033[92m"
    elif score >= 7:
        strength = "💪 VERY STRONG"
        color = "\033[92m"
    elif score >= 5:
        strength = "👍 STRONG"
        color = "\033[94m"
    elif score >= 3:
        strength = "⚠️  MEDIUM"
        color = "\033[93m"
    else:
        strength = "🚨 WEAK"
        color = "\033[91m"
    
    return score, strength, color, feedback, bonuses, vulnerabilities

def analyze_password(password):
    """Complete password analysis with all innovative features."""
    print("\n" + "═" * 60)
    print("🛡️  PASSGUARDIAN SECURITY ANALYSIS")
    print("═" * 60)
    
    # Basic strength check
    score, strength, color, feedback, bonuses, vulnerabilities = check_password_strength(password)
    
    # Display masked password and basic info
    print(f"\n📝 Password: {'•' * len(password)}")
    print(f"📏 Length: {len(password)} characters")
    print(f"🔢 Unique characters: {len(set(password))}")
    
    # Strength bar and score
    print(f"\n📊 Strength Score: {score}/10")
    print(f"   {create_strength_bar(score)}")
    print(f"   {color}{strength}\033[0m")
    
    # Entropy calculation
    crack_times, entropy = estimate_crack_time(password)
    print(f"\n🔐 Entropy: {entropy} bits")
    
    # Crack time estimates
    print("\n⏱️  Estimated Crack Time:")
    print(f"   • Online (throttled):    {crack_times['online_throttled']}")
    print(f"   • Online (unthrottled):  {crack_times['online_unthrottled']}")
    print(f"   • Offline (slow hash):   {crack_times['offline_slow']}")
    print(f"   • Offline (fast hash):   {crack_times['offline_fast']}")
    
    # Breach check
    print("\n🌐 Breach Database Check:")
    breached, count = check_breach_database(password)
    if breached is None:
        print("   ⚪ Could not connect to breach database")
    elif breached:
        print(f"   \033[91m🚨 ALERT: Password found in {count:,} data breaches!\033[0m")
        print("   \033[91m   This password has been compromised. Change it immediately!\033[0m")
    else:
        print("   \033[92m✅ Good news! Password not found in known breaches\033[0m")
    
    # Vulnerabilities
    if vulnerabilities:
        print("\n🔍 Pattern Analysis:")
        for severity, message in vulnerabilities:
            print(f"   {severity}: {message}")
    
    # Bonuses
    if bonuses:
        print("\n🌟 Security Bonuses:")
        for bonus in bonuses:
            print(f"   {bonus}")
    
    # Improvement suggestions
    if feedback:
        print("\n💡 Suggestions to Improve:")
        for item in feedback:
            print(f"   {item}")
    
    # Overall recommendation
    print("\n" + "─" * 60)
    if score >= 7 and not breached:
        print("✨ Overall: This password provides good security!")
    elif breached:
        print("⛔ Overall: CHANGE THIS PASSWORD IMMEDIATELY - It's been breached!")
    elif score < 5:
        print("⚠️  Overall: Consider using a stronger password")
    else:
        print("📈 Overall: Decent password, but could be improved")

def show_menu():
    """Display the main menu."""
    print("\n" + "═" * 60)
    print("🛡️  PASSGUARDIAN - Advanced Password Security Tool")
    print("═" * 60)
    print("\n📋 MENU:")
    print("   [1] 🔍 Check password strength")
    print("   [2] 🎲 Generate secure password")
    print("   [3] 📝 Generate memorable passphrase")
    print("   [4] 🌐 Check if password was breached")
    print("   [5] 📊 Compare multiple passwords")
    print("   [6] ❓ Security tips")
    print("   [0] 🚪 Exit")
    print("─" * 60)

def security_tips():
    """Display password security tips."""
    print("\n" + "═" * 60)
    print("🔐 PASSWORD SECURITY TIPS")
    print("═" * 60)
    tips = [
        "🔹 Use at least 12-16 characters for important accounts",
        "🔹 Never reuse passwords across different sites",
        "🔹 Use a password manager to store unique passwords",
        "🔹 Enable two-factor authentication (2FA) when available",
        "🔹 Avoid personal information (birthdays, names, etc.)",
        "🔹 Consider using passphrases - they're easier to remember",
        "🔹 Change passwords if you suspect a breach",
        "🔹 Don't share passwords via email or text",
        "🔹 Be cautious of phishing attempts asking for passwords",
        "🔹 Regularly check haveibeenpwned.com for breaches"
    ]
    for tip in tips:
        print(f"   {tip}")

def compare_passwords():
    """Compare strength of multiple passwords."""
    print("\n📊 PASSWORD COMPARISON")
    print("─" * 40)
    print("Enter passwords to compare (empty line to finish):")
    
    passwords = []
    while True:
        pwd = input(f"   Password {len(passwords)+1}: ")
        if not pwd:
            break
        passwords.append(pwd)
    
    if len(passwords) < 2:
        print("Need at least 2 passwords to compare!")
        return
    
    print("\n" + "─" * 60)
    print(f"{'#':<3} {'Score':<8} {'Entropy':<12} {'Strength':<20}")
    print("─" * 60)
    
    for i, pwd in enumerate(passwords, 1):
        score, strength, color, _, _, _ = check_password_strength(pwd)
        _, entropy = estimate_crack_time(pwd)
        # Remove emoji for cleaner table
        strength_clean = strength.split(' ')[-1]
        print(f"{i:<3} {score}/10{'':<4} {entropy:<12} {color}{strength_clean}\033[0m")
    
    # Find best
    scores = [check_password_strength(p)[0] for p in passwords]
    best_idx = scores.index(max(scores))
    print(f"\n🏆 Strongest: Password #{best_idx + 1}")

def main():
    """Main application loop."""
    show_menu()
    
    while True:
        choice = input("\n🔸 Enter your choice (0-6): ").strip()
        
        if choice == '0':
            print("\n👋 Thank you for using PassGuardian! Stay secure! 🔐")
            break
        
        elif choice == '1':
            password = input("\n🔑 Enter password to analyze: ")
            if password:
                analyze_password(password)
        
        elif choice == '2':
            print("\n🎲 SECURE PASSWORD GENERATOR")
            try:
                length = int(input("   Password length (default 16): ") or "16")
                length = max(8, min(64, length))
            except ValueError:
                length = 16
            
            symbols = input("   Include symbols? (y/n, default y): ").lower() != 'n'
            
            print("\n   Generated passwords:")
            for i in range(3):
                pwd = generate_secure_password(length, symbols)
                print(f"   {i+1}. {pwd}")
            print("\n   💡 Tip: Use a password manager to store these!")
        
        elif choice == '3':
            print("\n📝 PASSPHRASE GENERATOR")
            try:
                num_words = int(input("   Number of words (default 4): ") or "4")
                num_words = max(3, min(8, num_words))
            except ValueError:
                num_words = 4
            
            separator = input("   Separator (default '-'): ") or "-"
            
            print("\n   Generated passphrases:")
            for i in range(3):
                phrase = generate_passphrase(num_words, separator)
                print(f"   {i+1}. {phrase}")
            print("\n   💡 Tip: Passphrases are easier to remember and very secure!")
        
        elif choice == '4':
            password = input("\n🔑 Enter password to check for breaches: ")
            if password:
                print("\n   Checking breach database...")
                breached, count = check_breach_database(password)
                if breached is None:
                    print("   ⚪ Could not connect to breach database")
                elif breached:
                    print(f"   \033[91m🚨 BREACHED! Found in {count:,} data breaches!\033[0m")
                else:
                    print("   \033[92m✅ Not found in known breaches\033[0m")
        
        elif choice == '5':
            compare_passwords()
        
        elif choice == '6':
            security_tips()
        
        else:
            print("   ❌ Invalid choice. Please enter 0-6.")
        
        # Show mini menu reminder
        print("\n" + "─" * 40)
        print("Menu: [1]Check [2]Generate [3]Passphrase [4]Breach [5]Compare [6]Tips [0]Exit")

if __name__ == "__main__":
    main()