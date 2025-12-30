# SIMPLE PASSWORD STRENGTH CHECKER
import re

def check_password_strength(password):
    """Check password strength using simple rules"""
    
    score = 0
    feedback = []
    
    # Rule 1: Length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long")
    
    # Rule 2: Has uppercase
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one UPPERCASE letter")
    
    # Rule 3: Has lowercase
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one lowercase letter")
    
    # Rule 4: Has numbers
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9)")
    
    # Rule 5: Has special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one special character (!@#$% etc.)")
    
    # Determine strength
    if score == 5:
        strength = "💪 VERY STRONG"
        color = "\033[92m"  # Green
    elif score == 4:
        strength = "👍 STRONG"
        color = "\033[94m"  # Blue
    elif score == 3:
        strength = "⚠️  MEDIUM"
        color = "\033[93m"  # Yellow
    else:
        strength = "🚨 WEAK"
        color = "\033[91m"  # Red
    
    return score, strength, color, feedback

def main():
    print("🔐 PASSWORD STRENGTH CHECKER")
    print("=" * 30)
    
    while True:
        password = input("\nEnter a password to check (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            print("Goodbye! 👋")
            break
        
        score, strength, color, feedback = check_password_strength(password)
        
        print(f"\nPassword: {'*' * len(password)}")
        print(f"Length: {len(password)} characters")
        print(f"Score: {score}/5")
        print(f"Strength: {color}{strength}\033[0m")
        
        if feedback:
            print("\nSuggestions to improve:")
            for item in feedback:
                print(f"  {item}")
        
        # Generate a better password suggestion
        if score < 4:
            suggestion = password[:8]  # Take first 8 chars
            if not re.search(r'[A-Z]', suggestion):
                suggestion += 'A'
            if not re.search(r'[0-9]', suggestion):
                suggestion += '1'
            if not re.search(r'[!@#$]', suggestion):
                suggestion += '!'
            
            print(f"\n💡 Try something like: {suggestion[:12]}")

if __name__ == "__main__":
    main()