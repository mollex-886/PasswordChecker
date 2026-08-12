using System;
using System.Collections.Generic;
using System.Linq;

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
        // The StringComparer ignores case, so "Admin" and "admin" both flag as bad
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

    // 3. Core Engine
    public class PasswordAnalyzer
    {
        // The <IPasswordRule> tells C# exactly what is going inside this list
        private readonly List<IPasswordRule> _rules = new List<IPasswordRule>();
    
        public void AddRule(IPasswordRule rule) => _rules.Add(rule);

        // The <RuleResult> tells C# what type of list is being returned
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
            // 1. Initialize the engine exactly once
            var analyzer = new PasswordAnalyzer();
    
            // 2. Add the three rules
            analyzer.AddRule(new LengthRule(minimumLength: 12));
            analyzer.AddRule(new EntropyRule());
            analyzer.AddRule(new DictionaryRule("rockyou-sample.txt"));

            Console.Write("Enter a password to test: ");
    
            // 3. The ?? "" tells C# "if the input is null, just use an empty string" to fix the warnings
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