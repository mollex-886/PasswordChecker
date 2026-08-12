# PasswordChecker 

A modular, local static analysis tool built in C# that evaluates password security based on mathematical entropy, modern NIST guidelines, and real-world threat intelligence. 

Unlike traditional password validators that rely on outdated complexity rules, this engine calculates cryptographic unpredictability and actively cross-references inputs against known compromised databases.

##  Features

*   **Mathematical Entropy Calculation:** Computes the bits of entropy for a given string using `E = L * log2(R)`.
*   **Global Breach Check (HIBP API):** Securely queries the *Have I Been Pwned* API using **k-Anonymity** (SHA-1 hashing) to check against billions of breached credentials without exposing the user's password.
*   **Local Dictionary Check:** Utilizes a C# `HashSet` for highly optimized $O(1)$ time complexity lookups against local common password lists (e.g., `rockyou.txt`).
*   **Modular Architecture:** Built using the **Strategy Design Pattern**, allowing new security rules to be injected without modifying the core engine.

##  Architecture 

This project utilizes strict Object-Oriented Programming (OOP) principles. The core evaluation engine relies on the `IPasswordRule` interface.

*   `PasswordAnalyzer`: The central engine that aggregates and runs all injected strategies.
*   `EntropyRule`: Calculates the mathematical strength of the password based on its length and character pool.
*   `PwnedApiRule`: Handles secure HTTP requests and cryptographic hashing.
*   `DictionaryRule`: Parses local files and handles instantaneous threat matching.
*   `LengthRule`: Validates the password against NIST minimum length requirements.

##  Installation

Ensure you have the [.NET SDK](https://dotnet.microsoft.com/download) installed on your machine.

1. Clone the repository:
