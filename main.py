import streamlit as st
import re
import hashlib
import requests
from typing import Dict
import numpy as np
from collections import Counter

st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔒",
    layout="centered"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .password-strong { color: #0fff50; }
    .password-medium { color: #FFA500; }
    .password-weak { color: #FF0000; }
    .highlight { background-color: #f0f2f6; padding: 20px; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)


class PasswordStrengthAnalyzer:
    def __init__(self, password: str):
        self.password = password
        self.min_length = 8
        self.patterns = {
            'sequential_numbers': r'(?:\d{2,})',
            'sequential_letters': r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            'repeated_chars': r'(.)\1{2,}',
            'keyboard_patterns': r'(?:qwer|asdf|zxcv|tyui|ghjk|bnm|wasd)'
        }
        self.common_passwords = {'password123', '12345678', 'qwerty', 'admin123'}

    def check_length(self) -> Dict:
        """Check password length"""
        length = len(self.password)
        score = min(100, (length / 20) * 100)
        return {
            'score': score,
            'message': f'Length: {length} characters',
            'suggestion': 'Consider using a longer password' if length < self.min_length else ''
        }

    def check_complexity(self) -> Dict:
        """Check password complexity"""
        has_upper = bool(re.search(r'[A-Z]', self.password))
        has_lower = bool(re.search(r'[a-z]', self.password))
        has_digit = bool(re.search(r'\d', self.password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', self.password))

        score = sum([has_upper, has_lower, has_digit, has_special]) * 25
        missing = []
        if not has_upper: missing.append('uppercase letters')
        if not has_lower: missing.append('lowercase letters')
        if not has_digit: missing.append('numbers')
        if not has_special: missing.append('special characters')

        return {
            'score': score,
            'message': 'Character types: ' + ', '.join([
                '✓ Uppercase' if has_upper else '✗ Uppercase',
                '✓ Lowercase' if has_lower else '✗ Lowercase',
                '✓ Numbers' if has_digit else '✗ Numbers',
                '✓ Special' if has_special else '✗ Special'
            ]),
            'suggestion': f"Add {', '.join(missing)}" if missing else ''
        }

    def calculate_entropy(self) -> Dict:
        """Calculate password entropy"""
        char_counts = Counter(self.password)
        probabilities = [count / len(self.password) for count in char_counts.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities)
        score = min(100, entropy * 10)

        return {
            'score': score,
            'message': f'Entropy: {entropy:.2f} bits',
            'suggestion': 'Use more random characters' if score < 50 else ''
        }

    def check_patterns(self) -> Dict:
        """Check for common patterns"""
        found_patterns = []
        for pattern_name, pattern in self.patterns.items():
            if re.search(pattern, self.password.lower()):
                found_patterns.append(pattern_name.replace('_', ' '))

        score = 100 if not found_patterns else max(0, 100 - len(found_patterns) * 25)
        return {
            'score': score,
            'message': 'Patterns found: ' + (', '.join(found_patterns) if found_patterns else 'None'),
            'suggestion': 'Avoid common patterns' if found_patterns else ''
        }

    def check_haveibeenpwned(self) -> Dict:
        """Check if password has been exposed in data breaches"""
        sha1_hash = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        try:
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return {
                            'score': 0,
                            'message': f'Found in {count} data breaches!',
                            'suggestion': 'This password has been compromised, choose a different one'
                        }
        except requests.RequestException:
            pass

        return {
            'score': 100,
            'message': 'Not found in known data breaches',
            'suggestion': ''
        }

    def analyze(self) -> Dict:
        """Perform comprehensive password analysis"""
        length_check = self.check_length()
        complexity_check = self.check_complexity()
        entropy_check = self.calculate_entropy()
        pattern_check = self.check_patterns()
        breach_check = self.check_haveibeenpwned()

        final_score = (
                length_check['score'] * 0.2 +
                complexity_check['score'] * 0.3 +
                entropy_check['score'] * 0.2 +
                pattern_check['score'] * 0.2 +
                breach_check['score'] * 0.1
        )

        return {
            'score': final_score,
            'checks': {
                'length': length_check,
                'complexity': complexity_check,
                'entropy': entropy_check,
                'patterns': pattern_check,
                'breaches': breach_check
            }
        }


def main():
    st.title("🔒 Password Strength Analyzer")
    st.markdown("### Check how strong your password is!")

    # Password input with toggle visibility
    col1, col2 = st.columns([3, 1])
    with col1:
        password = st.text_input(
            "Enter your password",
            type="password" if not st.session_state.get('show_password', False) else "default",
            help="Your password is never stored or transmitted"
        )
    with col2:
        st.checkbox("Show password", key="show_password")

    if password:
        analyzer = PasswordStrengthAnalyzer(password)
        analysis = analyzer.analyze()
        score = analysis['score']

        # Display overall score with color
        st.markdown("### Overall Strength Score")
        score_color = (
            "password-strong" if score >= 80
            else "password-medium" if score >= 50
            else "password-weak"
        )
        st.markdown(f"<h2 class='{score_color}'>{score:.1f}%</h2>", unsafe_allow_html=True)

        # Display detailed analysis
        st.markdown("### Detailed Analysis")
        for check_name, check_data in analysis['checks'].items():
            with st.expander(f"📊 {check_name.title()} Analysis"):
                st.markdown(f"**Score:** {check_data['score']:.1f}%")
                st.markdown(f"**Details:** {check_data['message']}")
                if check_data['suggestion']:
                    st.markdown(f"**Suggestion:** {check_data['suggestion']}")

        # Show improvement suggestions
        st.markdown("### 💡 Suggestions for Improvement")
        suggestions = [check['suggestion'] for check in analysis['checks'].values() if check['suggestion']]
        if suggestions:
            for suggestion in suggestions:
                st.markdown(f"- {suggestion}")
        else:
            st.markdown("✅ Your password meets all our security criteria!")


if __name__ == "__main__":
    main()