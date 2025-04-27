import hashlib
import bcrypt
import time
import string
import argparse
import random
import re
import os
import getpass
import matplotlib.pyplot as plt
from itertools import product
from tqdm import tqdm  # For progress bars

class PasswordTester:
    def __init__(self, dictionary_path="rockyou.txt"):
        self.algorithms = {
            'plaintext': self.plaintext_hash,
            'sha256': self.sha256_hash, 
            'bcrypt': self.bcrypt_hash
        }
        self.dictionary = self.load_dictionary(dictionary_path)
    
    def load_dictionary(self, path):
        """Load a dictionary of common passwords."""
        try:
            with open(path, 'r', errors='ignore') as file:
                return [line.strip() for line in file]
        except FileNotFoundError:
            # Return a small sample dictionary if file not found
            print(f"Warning: Dictionary file {path} not found. Using built-in sample dictionary.")
            return ["password", "123456", "admin", "welcome", "qwerty", 
                    "letmein", "football", "iloveyou", "abc123", "monkey"]

    def plaintext_hash(self, password):
        """No hashing, just return the password (for comparison baseline)"""
        return password
    
    def sha256_hash(self, password):
        """Create a SHA-256 hash of the password"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def bcrypt_hash(self, password):
        """Create a bcrypt hash of the password"""
        salt = bcrypt.gensalt(rounds=10)  # Lower rounds for demonstration
        return bcrypt.hashpw(password.encode(), salt)
    
    def generate_hash(self, password, algorithm):
        """Generate a hash using the specified algorithm"""
        if algorithm in self.algorithms:
            return self.algorithms[algorithm](password)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
    
    def verify_hash(self, password, hash_value, algorithm):
        """Verify if a password matches a hash"""
        if algorithm == 'plaintext':
            return password == hash_value
        elif algorithm == 'sha256':
            return self.sha256_hash(password) == hash_value
        elif algorithm == 'bcrypt':
            return bcrypt.checkpw(password.encode(), hash_value)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
    
    def dictionary_attack(self, hash_value, algorithm, max_attempts=None):
        """Perform a dictionary attack on the given hash"""
        start_time = time.time()
        attempts = 0
        
        # Use a smaller subset of dictionary for bcrypt to avoid long wait times
        if algorithm == 'bcrypt' and max_attempts is None:
            max_attempts = min(10000, len(self.dictionary))
            
        # Create a progress bar
        total = max_attempts if max_attempts else len(self.dictionary)
        pbar = tqdm(total=total, desc=f"{algorithm} dictionary attack")
            
        for password in self.dictionary:
            attempts += 1
            pbar.update(1)
            
            if max_attempts and attempts > max_attempts:
                break
                
            if self.verify_hash(password, hash_value, algorithm):
                end_time = time.time()
                pbar.close()
                return {
                    'success': True,
                    'password': password,
                    'attempts': attempts,
                    'time': end_time - start_time
                }
                
            if attempts % 1000 == 0:
                pbar.set_description(f"{algorithm} dictionary attack - {attempts} attempts")
        
        end_time = time.time()
        pbar.close()
        return {
            'success': False,
            'attempts': attempts,
            'time': end_time - start_time
        }
    
    def brute_force_attack(self, hash_value, algorithm, charset=None, max_length=4, max_attempts=100000):
        """Perform a brute force attack on the given hash"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
            
        start_time = time.time()
        attempts = 0
        
        # For bcrypt, reduce the search space
        if algorithm == 'bcrypt':
            max_length = min(max_length, 3)  # Limit length for bcrypt to avoid extremely long runtime
            max_attempts = min(max_attempts, 10000)
            
        # Create a progress bar
        pbar = tqdm(total=max_attempts, desc=f"{algorithm} brute force attack")
        
        # Try different password lengths
        for length in range(1, max_length + 1):
            # Generate all possible combinations of the given length
            for attempt in product(charset, repeat=length):
                password = ''.join(attempt)
                attempts += 1
                pbar.update(1)
                
                if attempts > max_attempts:
                    end_time = time.time()
                    pbar.close()
                    return {
                        'success': False,
                        'attempts': attempts,
                        'time': end_time - start_time,
                        'max_attempts_reached': True
                    }
                
                if attempts % 1000 == 0:
                    pbar.set_description(f"{algorithm} brute force - length {length}, {attempts} attempts")
                
                if self.verify_hash(password, hash_value, algorithm):
                    end_time = time.time()
                    pbar.close()
                    return {
                        'success': True,
                        'password': password,
                        'attempts': attempts,
                        'time': end_time - start_time
                    }
        
        end_time = time.time()
        pbar.close()
        return {
            'success': False,
            'attempts': attempts,
            'time': end_time - start_time
        }
    
    def compare_algorithms(self, password, attack_type="dictionary", max_attempts=100000):
        """Compare the security of different algorithms for a given password"""
        results = {}
        
        for algorithm in self.algorithms:
            print(f"\nTesting {algorithm} hashing...")
            
            # Generate hash
            hash_start = time.time()
            hash_value = self.generate_hash(password, algorithm)
            hash_time = time.time() - hash_start
            
            # Run selected attack
            if attack_type == "dictionary":
                attack_result = self.dictionary_attack(hash_value, algorithm, max_attempts)
            else:  # brute-force
                attack_result = self.brute_force_attack(hash_value, algorithm, max_attempts=max_attempts)
            
            # Store results
            results[algorithm] = {
                'hash_time': hash_time,
                'attack_result': attack_result
            }
            
            # Print results
            print(f"  Hash generation time: {hash_time:.6f} seconds")
            if attack_result['success']:
                print(f"  Password cracked: {attack_result['password']}")
                print(f"  Attempts required: {attack_result['attempts']}")
                print(f"  Cracking time: {attack_result['time']:.2f} seconds")
            else:
                if attack_result.get('max_attempts_reached', False):
                    print(f"  Password not cracked (max attempts reached)")
                else:
                    print(f"  Password not cracked")
                print(f"  Attempts made: {attack_result['attempts']}")
                print(f"  Time spent: {attack_result['time']:.2f} seconds")
        
        return results
        
    def evaluate_password_strength(self, password):
        """
        Evaluate password strength based on multiple criteria
        Returns a score from 0-100 and feedback
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            feedback.append("Password is too short (should be at least 8 characters)")
        elif len(password) >= 12:
            score += 25
            feedback.append("Good password length")
        else:
            score += 15
            feedback.append("Password length is acceptable but could be improved")
            
        # Character variety checks
        if re.search(r'[A-Z]', password):
            score += 10
            feedback.append("Contains uppercase letters")
        else:
            feedback.append("Missing uppercase letters")
            
        if re.search(r'[a-z]', password):
            score += 10
            feedback.append("Contains lowercase letters")
        else:
            feedback.append("Missing lowercase letters")
            
        if re.search(r'[0-9]', password):
            score += 10
            feedback.append("Contains numbers")
        else:
            feedback.append("Missing numbers")
            
        if re.search(r'[^A-Za-z0-9]', password):
            score += 15
            feedback.append("Contains special characters")
        else:
            feedback.append("Missing special characters")
            
        # Common pattern check
        common_patterns = [
            r'123456', r'password', r'qwerty', r'admin', 
            r'welcome', r'abc123', r'letmein'
        ]
        if any(re.search(pattern, password.lower()) for pattern in common_patterns):
            score -= 20
            feedback.append("Contains common password patterns")
            
        # Dictionary check - check if password is in the top 1000 common passwords
        sample = self.dictionary[:min(1000, len(self.dictionary))]
        if password.lower() in [p.lower() for p in sample]:
            score -= 30
            feedback.append("Password found in common password lists")
            
        # Sequential characters check
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            score -= 10
            feedback.append("Contains sequential characters")
            
        # Repeated characters check
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("Contains repeated characters")
            
        # Ensure score is within 0-100 range
        score = max(0, min(100, score))
        
        # Overall rating
        rating = "Very Weak"
        if score >= 90:
            rating = "Very Strong"
        elif score >= 70:
            rating = "Strong"
        elif score >= 50:
            rating = "Moderate"
        elif score >= 30:
            rating = "Weak"
            
        # Suggestions for improvement
        suggestions = []
        if score < 70:
            if len(password) < 12:
                suggestions.append("Use a longer password (at least 12 characters)")
            if not re.search(r'[A-Z]', password):
                suggestions.append("Add uppercase letters")
            if not re.search(r'[a-z]', password):
                suggestions.append("Add lowercase letters")
            if not re.search(r'[0-9]', password):
                suggestions.append("Add numbers")
            if not re.search(r'[^A-Za-z0-9]', password):
                suggestions.append("Add special characters (!@#$%^&*)")
            if score < 50:
                suggestions.append("Consider using a randomly generated password")
                
        return {
            'score': score,
            'rating': rating,
            'feedback': feedback,
            'suggestions': suggestions
        }
    
    def suggest_secure_password(self, length=16):
        """Generate a secure random password"""
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(length))
        return password
    
    def visualize_performance(self, results, password=None):
        """Visualize the performance differences between algorithms with password insights"""
    # Create a figure with 3 subplots - hash time, crack time, and password analysis
        fig = plt.figure(figsize=(16, 10))

        # Define grid layout
        gs = plt.GridSpec(2, 2, figure = fig)
        ax1 = fig.add_subplot(gs[0, 0])  # Hash time
        ax2 = fig.add_subplot(gs[0, 1])  # Crack time
        ax3 = fig.add_subplot(gs[1, :])  # Password analysis
    
        # Extract data
        algorithms = list(results.keys())
        hash_times = [results[algo]['hash_time'] for algo in algorithms]
        crack_times = [results[algo]['attack_result']['time'] for algo in algorithms]
        attempts = [results[algo]['attack_result']['attempts'] for algo in algorithms]
    
        # Determine which passwords were cracked
        cracked = [results[algo]['attack_result'].get('success', False) for algo in algorithms]
    
        # Use different colors for cracked vs uncracked
        colors = ['green' if success else 'red' for success in cracked]
    
        # Plot hash generation times
        ax1.bar(algorithms, hash_times)
        ax1.set_title('Hash Generation Time')
        ax1.set_ylabel('Time (seconds)')
        ax1.set_yscale('log')  # Logarithmic scale for better visualization
    
        # Plot cracking times
        bars = ax2.bar(algorithms, crack_times, color=colors)
        ax2.set_title('Password Cracking Time')
        ax2.set_ylabel('Time (seconds)')
        ax2.set_yscale('log')  # Logarithmic scale for better visualization
    
        # Add attempt counts as text on the bars
        for i, (bar, attempt, success) in enumerate(zip(bars, attempts, cracked)):
            height = bar.get_height()
            status = "CRACKED" if success else "NOT CRACKED"
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{attempts[i]} attempts\n{status}',
                    ha='center', va='bottom', rotation=0)
    
        # Add password analysis section
            if password:
                self._add_password_analysis(ax3, password, results, cracked)
            else:
                ax3.text(0.5, 0.5, "No password provided for analysis", 
                    ha='center', va='center', fontsize=14)
            ax3.axis('off')
    
        plt.tight_layout()
    
        # Save the figure
        plt.savefig('password_security_comparison.png')
        print("\nVisualization saved as 'password_security_comparison.png'")
    
        # Display if in interactive environment
        try:
            plt.show()
        except:
            pass

def _add_password_analysis(self, ax, password, results, cracked):
    """Add password analysis to the chart"""
    ax.axis('off')  # Turn off axis
    
    # Evaluate password strength
    strength = self.evaluate_password_strength(password)
    
    # Calculate the mask for the password (show first and last chars)
    masked_password = self._mask_password(password)
    
    # Create sections for the text
    title = f"Password Analysis: {masked_password}"
    strength_text = f"Strength Score: {strength['score']}/100 ({strength['rating']})"
    
    # Prepare feedback and algorithm results
    feedback_items = strength['feedback']
    cracking_results = []
    
    for i, algo in enumerate(results.keys()):
        status = "CRACKED" if cracked[i] else "NOT CRACKED"
        time_taken = results[algo]['attack_result']['time']
        attempts = results[algo]['attack_result']['attempts']
        
        if cracked[i]:
            cracking_results.append(
                f"• {algo.upper()}: {status} in {time_taken:.2f}s after {attempts} attempts"
            )
        else:
            cracking_results.append(
                f"• {algo.upper()}: {status} after {attempts} attempts ({time_taken:.2f}s)"
            )
    
    # Analyze the results to provide insights
    insights = self._generate_insights(password, strength, results, cracked)
    
    # Layout the text in the chart
    ax.text(0.5, 0.95, title, fontsize=16, weight='bold', ha='center', transform=ax.transAxes)
    ax.text(0.5, 0.88, strength_text, fontsize=14, ha='center', transform=ax.transAxes)
    
    # Feedback column (left)
    ax.text(0.25, 0.80, "Password Characteristics:", fontsize=13, weight='bold', ha='center', transform=ax.transAxes)
    for i, item in enumerate(feedback_items):
        ax.text(0.25, 0.75 - i*0.05, f"• {item}", fontsize=11, ha='center', transform=ax.transAxes)
    
    # Results column (right)
    ax.text(0.75, 0.80, "Cracking Results:", fontsize=13, weight='bold', ha='center', transform=ax.transAxes)
    for i, result in enumerate(cracking_results):
        ax.text(0.75, 0.75 - i*0.05, result, fontsize=11, ha='center', transform=ax.transAxes)
    
    # Insights at the bottom
    ax.text(0.5, 0.35, "Analysis Insights:", fontsize=13, weight='bold', ha='center', transform=ax.transAxes)
    for i, insight in enumerate(insights):
        ax.text(0.5, 0.30 - i*0.05, f"• {insight}", fontsize=11, ha='center', transform=ax.transAxes)

def _mask_password(self, password):
    """Create a masked version of the password for display"""
    if len(password) <= 4:
        return "*" * len(password)  # Mask completely if too short
    
    return password[0] + "*" * (len(password) - 2) + password[-1]

def _generate_insights(self, password, strength, results, cracked):
    """Generate insights based on the password test results"""
    insights = []
    
    # Check if password was cracked
    if any(cracked):
        cracked_algos = [algo.upper() for algo, was_cracked in zip(results.keys(), cracked) if was_cracked]
        insights.append(f"Your password was cracked using {', '.join(cracked_algos)}.")
        
        # Add specific insights based on which algorithm was cracked
        if 'plaintext' in cracked_algos:
            insights.append("Storing passwords as plaintext is never secure - even strong passwords are instantly compromised.")
        
        if 'sha256' in cracked_algos:
            insights.append("Fast hashing algorithms like SHA-256 are vulnerable to high-speed cracking attempts.")
        
        # Check if it was in common dictionaries
        if password.lower() in [p.lower() for p in self.dictionary[:1000]]:
            insights.append("Your password appears in common password lists, making it vulnerable to dictionary attacks.")
    else:
        # Not cracked - explain why
        if 'bcrypt' not in cracked and 'bcrypt' in results:
            insights.append("Bcrypt's intentional slowness protected your password from being cracked.")
        
        if strength['score'] >= 70:
            insights.append("Your password's strength helped it resist cracking attempts.")
    
    # Add insights based on password composition
    if strength['score'] < 50:
        insights.append("Low strength score indicates your password could be vulnerable to more extensive attacks.")
    
    if len(password) < 10:
        insights.append("Short passwords are generally easier to crack through brute force methods.")
    
    # Pattern-based insights
    if re.search(r'[0-9]{4}', password):
        insights.append("Number sequences (like years) are common patterns that attackers check first.")
    
    if re.search(r'(.)\1{2,}', password):
        insights.append("Repeated characters weaken passwords by making them more predictable.")
    
    # Add recommendations
    if strength['suggestions']:
        insights.append(f"Recommendation: {strength['suggestions'][0]}")
    
    # Ensure we don't have too many insights
    if len(insights) > 5:
        return insights[:5]
    
    # If we have very few insights, add a general one
    if len(insights) < 2:
        insights.append("Using unique, long passwords with a mix of character types is generally recommended.")
    
    return insights

def interactive_mode():
    """Interactive mode for the password tester"""
    print("\n=====================================================")
    print("= Interactive Password Security Testing Tool =")
    print("=====================================================")
    print("This tool is for EDUCATIONAL PURPOSES ONLY")
    print("=====================================================\n")
    
    # Check for rockyou.txt
    dict_file = 'rockyou.txt'
    if not os.path.exists(dict_file):
        print("Note: rockyou.txt not found in the current directory.")
        print("You can download it from various security resources or use a different wordlist.")
        print("For now, using a small built-in sample dictionary.\n")
    
    # Initialize the tester
    tester = PasswordTester(dict_file)
    
    while True:
        print("\nWhat would you like to do?")
        print("1. Test my password strength (no cracking)")
        print("2. Get a suggested secure password")
        print("3. Test my password against dictionary attack")
        print("4. Test my password against brute force attack")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == '1':
            # Evaluate password strength
            print("\nPassword strength evaluation:")
            password = getpass.getpass("Enter your password (input will be hidden): ")
            
            strength = tester.evaluate_password_strength(password)
            print(f"\nStrength score: {strength['score']}/100 - {strength['rating']}")
            
            print("\nFeedback:")
            for item in strength['feedback']:
                print(f"- {item}")
            
            if strength['suggestions']:
                print("\nSuggestions for improvement:")
                for suggestion in strength['suggestions']:
                    print(f"- {suggestion}")
        
        elif choice == '2':
            # Suggest a secure password
            length = input("Enter desired password length (default is 16): ")
            try:
                length = int(length)
                if length < 8:
                    print("Password length should be at least 8 characters. Using 16 instead.")
                    length = 16
            except ValueError:
                print("Using default length of 16 characters.")
                length = 16
                
            secure_password = tester.suggest_secure_password(length)
            print(f"\nSuggested secure password: {secure_password}")
            
            strength = tester.evaluate_password_strength(secure_password)
            print(f"Strength score: {strength['score']}/100 - {strength['rating']}")
        
        elif choice == '3' or choice == '4':
            # Dictionary or brute force attack
            print("\nWARNING: This will attempt to crack your password!")
            print("This is for educational purposes only and may take some time.")
            password = getpass.getpass("Enter your password (input will be hidden): ")
    
            if not password:
                print("No password entered. Returning to menu.")
                continue
            
            # Ask for max attempts
            max_attempts = input("Enter maximum number of attempts (default 10000): ")
            try:
                max_attempts = int(max_attempts)
            except ValueError:
                print("Using default of 10000 attempts.")
                max_attempts = 10000
            
            # Perform attack
            attack_type = "dictionary" if choice == '3' else "brute"
            print(f"\nRunning {attack_type} attack (max {max_attempts} attempts)...")
            results = tester.compare_algorithms(password, attack_type, max_attempts)
            
            # Print summary
            print("\nSUMMARY")
            print("-------")
            for algorithm, result in results.items():
                status = "CRACKED" if result['attack_result']['success'] else "SECURE"
                attempts = result['attack_result']['attempts']
                time_taken = result['attack_result']['time']
                print(f"{algorithm.upper()}: {status} - {attempts} attempts in {time_taken:.2f} seconds")
                
            # Visualize results - now passing the password
            try:
                tester.visualize_performance(results, password)
            except Exception as e:
                print(f"Could not generate visualization: {e}")

def main():
    parser = argparse.ArgumentParser(description='Password Security Testing Tool')
    parser.add_argument('--password', type=str, help='Password to test')
    parser.add_argument('--attack', choices=['dictionary', 'brute'], default='dictionary',
                        help='Attack type (dictionary or brute force)')
    parser.add_argument('--max-attempts', type=int, default=100000,
                        help='Maximum number of attempts')
    parser.add_argument('--dict-file', type=str, default='rockyou.txt',
                        help='Path to dictionary file')
    parser.add_argument('--evaluate', action='store_true',
                        help='Evaluate password strength without cracking')
    parser.add_argument('--suggest', action='store_true',
                        help='Suggest a secure password')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Run in interactive mode')
    args = parser.parse_args()
    
    # Run in interactive mode if requested or if no arguments provided
    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
        return
    
    print("\n=====================================================")
    print("= Password Security Testing Tool - Educational Use Only =")
    print("=====================================================\n")
    
    # Check for rockyou.txt
    if args.dict_file == 'rockyou.txt' and not os.path.exists('rockyou.txt'):
        print("Note: rockyou.txt not found in the current directory.")
        print("You can download it from various security resources or use a different wordlist.")
        print("For now, using a small built-in sample dictionary.\n")
    
    tester = PasswordTester(args.dict_file)
    
    # Suggest a secure password if requested
    if args.suggest:
        secure_password = tester.suggest_secure_password()
        print(f"Suggested secure password: {secure_password}")
        strength = tester.evaluate_password_strength(secure_password)
        print(f"Strength score: {strength['score']}/100 - {strength['rating']}")
        return
    
    # Use provided password or prompt for one
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter your password (input will be hidden): ")
        if not password:
            print("No password entered. Exiting.")
            return
    
    # Evaluate password strength if requested
    if args.evaluate:
        print("\nEvaluating password strength:")
        strength = tester.evaluate_password_strength(password)
        print(f"Strength score: {strength['score']}/100 - {strength['rating']}")
        print("\nFeedback:")
        for item in strength['feedback']:
            print(f"- {item}")
        
        if strength['suggestions']:
            print("\nSuggestions for improvement:")
            for suggestion in strength['suggestions']:
                print(f"- {suggestion}")
        return
        
    print(f"\nComparing algorithms using {args.attack} attack (max {args.max_attempts} attempts)...")
    results = tester.compare_algorithms(password, args.attack, args.max_attempts)

    # Print summary
    print("\nSUMMARY")
    print("-------")
    for algorithm, result in results.items():
        status = "CRACKED" if result['attack_result']['success'] else "SECURE"
        attempts = result['attack_result']['attempts']
        time_taken = result['attack_result']['time']
        print(f"{algorithm.upper()}: {status} - {attempts} attempts in {time_taken:.2f} seconds")

    # Visualize results - now passing the password
    tester.visualize_performance(results, password)


if __name__ == "__main__":
    import sys
    main()