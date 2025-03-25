"""
Password Strength Module

This module provides classes for checking password strength and generating secure passwords.
It includes:
- Wordlist: A class to handle wordlists for checking weak or banned passwords.
- StrengthResult: A class to store the results of a password strength check.
- PasswordStrength: A class to check password strength and generate random passwords.
"""

import re
import secrets
import string
import logging
from functools import lru_cache
from zxcvbn import zxcvbn

# Configure basic logging; can be overridden in app.py if needed
logging.basicConfig(
    filename='password_checker.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class Wordlist:
    """Class to handle wordlists for password checking."""

    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    def load_wordlist(self):
        """Load wordlist from file."""
        if self.file_path in self._cache:
            return self._cache[self.file_path]

        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                wordlist = [line.strip() for line in file]
                self._cache[self.file_path] = wordlist
                return wordlist
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Error: File '{self.file_path}' not found.") from e
        except Exception as e:
            raise RuntimeError(f"Error loading wordlist from '{self.file_path}': {str(e)}") from e

    def is_word_in_list(self, word):
        """Check if a word is in the wordlist."""
        return word in self.words

class StrengthResult:
    """Class to store password strength check results."""

    def __init__(self, strength: str, score: int, message: str):
        self.strength = strength
        self.score = score
        self.message = message

class PasswordStrength:
    """Class to handle password strength checking and related operations."""

    def __init__(self, weak_wordlist_path: str = None, banned_wordlist_path: str = None):
        """
        Initialize the PasswordStrength class.

        Args:
            weak_wordlist_path (str, optional): Path to the weak passwords wordlist.
            banned_wordlist_path (str, optional): Path to the banned passwords wordlist.
        """
        self.weak_wordlist = None
        self.banned_wordlist = None
        if weak_wordlist_path:
            try:
                self.weak_wordlist = Wordlist(weak_wordlist_path)
            except Exception as e:
                logging.error(f"Failed to load weak wordlist: {e}")
        if banned_wordlist_path:
            try:
                self.banned_wordlist = Wordlist(banned_wordlist_path)
            except Exception as e:
                logging.error(f"Failed to load banned wordlist: {e}")
        self.min_password_length = 12
        self.strength_mapping = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

    @lru_cache(maxsize=1000)
    def check_password_strength(self, password: str) -> StrengthResult:
        """Check the strength of a given password.

        Args:
            password (str): The password to check.

        Returns:
            StrengthResult: An object containing strength, score, and message.
        """
        if len(password) < self.min_password_length:
            return StrengthResult("Too short", 0, "Password should be at least 12 characters long.")

        if self.weak_wordlist and self.weak_wordlist.is_word_in_list(password):
            return StrengthResult("Weak", 0, "Password is commonly used and easily guessable.")

        if self.banned_wordlist and self.banned_wordlist.is_word_in_list(password):
            return StrengthResult("Banned", 0, "This password is not allowed, as it is commonly found in data leaks.")

        password_strength = zxcvbn(password)
        score = password_strength["score"]
        strength = self.strength_mapping[score]
        complexity_issues = []
        if not re.search(r'[A-Z]', password):
            complexity_issues.append("uppercase letter")
        if not re.search(r'[a-z]', password):
            complexity_issues.append("lowercase letter")
        if not re.search(r'\d', password):
            complexity_issues.append("number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            complexity_issues.append("special character")

        if complexity_issues:
            return StrengthResult("Weak", score, f"Password lacks complexity. Missing: {', '.join(complexity_issues)}.")

        if score >= 3:
            return StrengthResult(strength, score, f"Password meets all the requirements. Score: {score}/4")

        suggestions = password_strength["feedback"]["suggestions"]
        return StrengthResult(strength, score, f"Password is {strength.lower()}. Suggestions: {', '.join(suggestions)}")

    def generate_random_password(self, length: int = 16) -> str:
        """Generate a cryptographically secure random password.

        Args:
            length (int): Length of the password (default: 16).

        Returns:
            str: A randomly generated password.
        """
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(length))

    def suggest_improvements(self, password: str) -> str:
        """Suggest improvements for a given password.

        Args:
            password (str): The password to analyze.

        Returns:
            str: A formatted string with improvement suggestions.
        """
        result = self.check_password_strength(password)
        suggestions = []

        if len(password) < self.min_password_length:
            suggestions.append(f"Increase length to at least {self.min_password_length} characters")
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        if not re.search(r'\d', password):
            suggestions.append("Add numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            suggestions.append("Add special characters")

        if not suggestions:
            suggestions = result.message.split("Suggestions: ")[-1].split(", ")

        return "Suggested improvements:\n\n" + "\n".join(f"- {s}" for s in suggestions)