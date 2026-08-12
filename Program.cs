using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace PasswordChecker
{
    // 1. Data Model & Interface
    public class RuleResult
    {
        public bool IsPassed { get; set; }
        public int Score { get; set; }
        public string Feedback { get; set; }

        public RuleResult(bool isPassed, int score, string feedback)
        {
            IsPassed = isPassed;
            Score = score;
            Feedback = feedback;
        }
    }

    public interface IPasswordRule
    {
        RuleResult Evaluate(string password);
    }

    // 2. Concrete Rules
    public class LengthRule : IPasswordRule
    {
        private readonly int _minimumLength;
        public LengthRule(int minimumLength = 12) => _minimumLength = minimumLength;

        public RuleResult Evaluate(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < _minimumLength)
                return new RuleResult(false, 0, $"Password must be at least {_minimumLength} characters long.");
            
            int scoreBonus = (password.Length - _minimumLength) * 5; 
            return new RuleResult(true, 50 + scoreBonus, "Length is acceptable.");
        }
    }

    public class EntropyRule : IPasswordRule
    {
        public RuleResult Evaluate(string password)
        {
            if (string.IsNullOrEmpty(password)) return new RuleResult(false, 0, "Empty password.");

            int poolSize = CalculatePoolSize(password);
            double entropy = password.Length * Math.Log2(poolSize);

            if (entropy < 50) return new RuleResult(false, (int)entropy, $"Weak entropy ({(int)entropy} bits). Add mixed characters.");
            return new RuleResult(true, (int)entropy, $"Strong entropy ({(int)entropy} bits).");
        }

        private int CalculatePoolSize(string password)
        {
            int pool = 0;
            if (password.Any(char.IsLower)) pool += 26;
            if (password.Any(char.IsUpper)) pool += 26;
            if (password.Any(char.IsDigit)) pool += 10;
            if (password.Any(ch => !char.IsLetterOrDigit(ch))) pool += 32;
            return pool == 0 ? 1 : pool;
        }
    }

    public class DictionaryRule : IPasswordRule
    {
        private readonly HashSet<string> _commonPasswords;

        public DictionaryRule(string filePath)
        {
            _commonPasswords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
            if (System.IO.File.Exists(filePath))
            {
                foreach (var line in System.IO.File.ReadLines(filePath))
                {
                    _commonPasswords.Add(line.Trim());
                }
            }
            else
            {
                Console.WriteLine($"[WARNING] Dictionary file not found at: {filePath}");
            }
        }

        public RuleResult Evaluate(string password)
        {
            if (_commonPasswords.Contains(password))
            {
                return new RuleResult(false, -50, "CRITICAL: Password found in dictionary list!");
            }
            return new RuleResult(true, 10, "Password not found in known dictionary.");
        }
    }

    public class PwnedApiRule : IPasswordRule
    {
        private static readonly HttpClient client = new HttpClient();

        public PwnedApiRule()
        {
            if (!client.DefaultRequestHeaders.Contains("User-Agent"))
            {
                client.DefaultRequestHeaders.Add("User-Agent", "CSharp-Security-Portfolio-Project");
            }
        } // <-- This was the missing bracket!

        public RuleResult Evaluate(string password)
        {
            if (string.IsNullOrEmpty(password)) return new RuleResult(false, 0, "Empty password.");

            // 1. Calculate the SHA-1 hash
            string hash = ComputeSha1(password);
            string prefix = hash.Substring(0, 5);
            string suffix = hash.Substring(5);

            try
            {
                // 2. Query the API securely using only the 5-character prefix
                string url = $"https://api.pwnedpasswords.com/range/{prefix}";
                string response = client.GetStringAsync(url).Result;

                // 3. Search the returned list for our specific suffix
                if (response.Contains(suffix))
                {
                    return new RuleResult(false, -100, "CRITICAL: Password found in global breached database (HIBP)!");
                }
                
                return new RuleResult(true, 20, "Password is safe from known public breaches.");
            }
            catch (Exception ex)
            {
                return new RuleResult(true, 0, $"[API Skipped] Network error: {ex.Message}");
            }
        }

        // Helper method to generate the SHA-1 hash
        private string ComputeSha1(string input)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = sha1.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToUpper();
            }
        }
    }

    // 3. Core Engine
    public class PasswordAnalyzer
    {
        private readonly List<IPasswordRule> _rules = new List<IPasswordRule>();
    
        public void AddRule(IPasswordRule rule) => _rules.Add(rule);

        public List<RuleResult> Analyze(string password)
        {
            var report = new List<RuleResult>();
            foreach (var rule in _rules) report.Add(rule.Evaluate(password));
            return report;
        }
    }

    // 4. Main Program Execution
    class Program
    {
        static void Main(string[] args)
        {
            var analyzer = new PasswordAnalyzer();
    
            analyzer.AddRule(new LengthRule(minimumLength: 12));
            analyzer.AddRule(new EntropyRule());
            analyzer.AddRule(new DictionaryRule("rockyou-sample.txt"));
            analyzer.AddRule(new PwnedApiRule()); // <-- Added this so the API actually runs!

            Console.Write("Enter a password to test: ");
            string testPassword = Console.ReadLine() ?? "";

            var results = analyzer.Analyze(testPassword);

            Console.WriteLine("\n--- Security Analysis Report ---");
            bool isSecure = true;
    
            foreach (var result in results)
            {
                string status = result.IsPassed ? "[PASS]" : "[FAIL]";
                Console.WriteLine($"{status} Score: {result.Score,-3} | {result.Feedback}");
                if (!result.IsPassed) isSecure = false;
            }

            Console.WriteLine("--------------------------------");
            Console.WriteLine(isSecure ? "FINAL: PASSWORD APPROVED" : "FINAL: PASSWORD REJECTED");
        }
    }
}