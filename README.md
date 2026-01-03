#  PassGuardian – Smart Password Security Tool

**PassGuardian** is an advanced, menu-driven password security analyzer that helps users **evaluate, generate, and improve password strength** using real-world security techniques. It combines breach detection, entropy analysis, crack-time estimation, and secure password generation in one tool.

##  Features

* **Have I Been Pwned Integration**
  Checks if a password appeared in known data breaches using **k-anonymity** (only first 5 hash characters sent).

*  **Entropy-Based Strength Analysis**
  Calculates true randomness of passwords in bits.

*  **Crack Time Estimation**
  Estimates time to crack passwords under:

  * Online (throttled & unthrottled)
  * Offline slow hashing (bcrypt)
  * Offline fast hashing (MD5)

*  **Pattern Detection**
  Detects common passwords, keyboard patterns, sequences, repeated characters, date patterns, and leet-speak.

*  **Secure Password Generator**
  Generates cryptographically secure random passwords using the `secrets` module.

*  **Passphrase Generator**
  Creates memorable yet strong passphrases like:
  `Dragon-Sunset-Crystal-42`

*  **Password Comparison**
  Compare multiple passwords side-by-side.

*  **Visual Strength Bar**
  ASCII progress bar for easy understanding.

*  **Security Tips**
  Built-in best practices for password safety.

## Menu Interface

```
[1] 🔍 Check password strength
[2] 🎲 Generate secure password
[3] 📝 Generate memorable passphrase
[4] 🌐 Check if password was breached
[5] 📊 Compare multiple passwords
[6] ❓ Security tips
[0] 🚪 Exit
```

##  Tech Stack

* Python
* hashlib, secrets, math, requests
* Have I Been Pwned API (k-anonymity)

## 🔒 Privacy & Security

* Passwords are never stored
* No plaintext passwords are sent online
* Breach checks are privacy-safe
