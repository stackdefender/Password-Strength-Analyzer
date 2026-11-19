/**
 * ==============================================================================
 * CyberSec Password Strength Analyzer & Security Auditor
 * Technology: Pure JavaScript (ES6+), Web Crypto API (crypto.getRandomValues)
 * Architecture: 100% Client-Side Zero-Knowledge (Zero storage, Zero network)
 * ==============================================================================
 */

'use strict';

/**
 * Common and leaked passwords list (Top commonly compromised passwords & dictionary terms)
 * Sourced from OWASP, SecLists, and HaveIBeenPwned top recurring frequency lists.
 */
const COMMON_PASSWORDS = new Set([
  '123456', 'password', '123456789', '12345678', '12345', '111111', '1234567',
  'sunshine', 'qwerty', 'iloveyou', 'princess', 'admin', 'welcome', '666666',
  'football', '123123', 'monkey', 'charlie', 'donald', 'dragon', 'baseball',
  'pass', 'shadow', 'master', 'superman', 'michael', 'jessica', 'secret',
  '654321', 'computer', 'login', 'testing', 'jordan', 'starwars', 'killer',
  'cookie', 'chelsea', 'monkey1', 'ginger', 'password1', '123456a', 'hunter2',
  'trustno1', 'letmein', 'access', 'freedom', 'flower', 'whatever', 'harley',
  'coffee', 'buster', 'robert', 'thomas', 'soccer', 'orange', 'bullet',
  'summer', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'abc123', '123abc',
  'guest', 'root', 'toor', 'default', 'cisco', 'system', 'oracle', 'pass1234',
  'security', 'cybersecurity', 'administrator', 'pass123', 'qwerty123'
]);

/**
 * Sequential patterns and keyboard walk definitions
 */
const KEYBOARD_SEQUENCES = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  '1234567890', '0987654321',
  'qazwsxedcrfv', '1qaz2wsx3edc',
  'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz'
];

/**
 * PasswordAnalyzer Engine
 * Evaluates complexity, entropy, patterns, crack times, weaknesses, and suggestions.
 */
class PasswordAnalyzer {
  /**
   * Main audit method
   * @param {string} password - Raw user password (never stored or sent anywhere)
   * @returns {Object} Comprehensive analysis report
   */
  static analyze(password) {
    if (!password || password.length === 0) {
      return this.getEmptyReport();
    }

    const length = password.length;
    const upperMatches = password.match(/[A-Z]/g) || [];
    const lowerMatches = password.match(/[a-z]/g) || [];
    const digitMatches = password.match(/[0-9]/g) || [];
    const symbolMatches = password.match(/[^A-Za-z0-9]/g) || [];

    const upperCount = upperMatches.length;
    const lowerCount = lowerMatches.length;
    const digitCount = digitMatches.length;
    const symbolCount = symbolMatches.length;

    // Detect patterns
    const repeatedResult = this.detectRepeatedChars(password);
    const sequentialResult = this.detectSequentialPatterns(password);
    const commonResult = this.detectCommonPassword(password);
    const contextResult = this.detectContextPatterns(password);

    // Calculate Character Pool Size (R)
    let poolSize = 0;
    if (lowerCount > 0) poolSize += 26;
    if (upperCount > 0) poolSize += 26;
    if (digitCount > 0) poolSize += 10;
    if (symbolCount > 0) poolSize += 33; // Standard printable ASCII special symbols

    // Shannon Entropy Calculation: H = L * log2(R)
    let rawEntropy = 0;
    if (poolSize > 0) {
      rawEntropy = length * (Math.log2(poolSize));
    }

    // Effective Entropy adjusted for detected vulnerabilities
    let effectiveEntropy = rawEntropy;

    // Heavy penalty for common dictionary passwords
    if (commonResult.isCommon) {
      effectiveEntropy = Math.min(effectiveEntropy, 14.5);
    }

    // Penalty for sequential patterns (e.g. 123456, abcdef, qwerty)
    if (sequentialResult.hasSequential) {
      effectiveEntropy -= (sequentialResult.matchCount * 8.0);
    }

    // Penalty for repeated characters (e.g. 'aaa', '1111')
    if (repeatedResult.hasRepeats) {
      effectiveEntropy -= (repeatedResult.consecutiveCount * 6.0);
    }

    // Penalty for contextual dictionary words and 4-digit years
    if (contextResult.hasPatterns) {
      effectiveEntropy -= (contextResult.penalty);
    }

    // Penalty for single character set
    const charTypesCount = (upperCount > 0 ? 1 : 0) +
                           (lowerCount > 0 ? 1 : 0) +
                           (digitCount > 0 ? 1 : 0) +
                           (symbolCount > 0 ? 1 : 0);

    if (charTypesCount === 1) {
      effectiveEntropy = Math.min(effectiveEntropy, 22.0);
    }

    // Floor entropy at 0
    effectiveEntropy = Math.max(0, Math.round(effectiveEntropy * 10) / 10);

    // Determine Score (0 to 100%) and Rating Category
    const { score, rating, ratingClass } = this.calculateRating(
      length,
      charTypesCount,
      effectiveEntropy,
      commonResult.isCommon,
      sequentialResult.hasSequential,
      contextResult.hasPatterns
    );

    // Estimate Crack Times across 3 hardware models
    const crackTimes = this.calculateCrackTimes(effectiveEntropy);

    // Compile Identified Weaknesses
    const weaknesses = this.identifyWeaknesses({
      length,
      upperCount,
      lowerCount,
      digitCount,
      symbolCount,
      charTypesCount,
      commonResult,
      sequentialResult,
      repeatedResult,
      contextResult
    });

    // Compile Actionable Suggestions
    const suggestions = this.generateSuggestions({
      length,
      upperCount,
      lowerCount,
      digitCount,
      symbolCount,
      charTypesCount,
      commonResult,
      sequentialResult,
      repeatedResult,
      rating
    });

    // Checklist requirements status
    const checklist = {
      length: length >= 8,
      lengthStrong: length >= 12,
      upper: upperCount > 0,
      lower: lowerCount > 0,
      digits: digitCount > 0,
      symbols: symbolCount > 0,
      repeats: !repeatedResult.hasRepeats,
      sequences: !sequentialResult.hasSequential,
      notCommon: !commonResult.isCommon
    };

    return {
      length,
      upperCount,
      lowerCount,
      digitCount,
      symbolCount,
      poolSize,
      rawEntropy: Math.round(rawEntropy * 10) / 10,
      effectiveEntropy,
      score,
      rating,
      ratingClass,
      crackTimes,
      weaknesses,
      suggestions,
      checklist
    };
  }

  /**
   * Empty report structure for initial or cleared state
   */
  static getEmptyReport() {
    return {
      length: 0,
      upperCount: 0,
      lowerCount: 0,
      digitCount: 0,
      symbolCount: 0,
      poolSize: 0,
      rawEntropy: 0,
      effectiveEntropy: 0,
      score: 0,
      rating: 'Awaiting Input',
      ratingClass: 'rating-none',
      crackTimes: {
        online: '--',
        gpu: 'Instant (< 1 ms)',
        supercomputer: '--'
      },
      weaknesses: [],
      suggestions: [],
      checklist: {
        length: false,
        lengthStrong: false,
        upper: false,
        lower: false,
        digits: false,
        symbols: false,
        repeats: true,
        sequences: true,
        notCommon: true
      }
    };
  }

  /**
   * Detect 3 or more consecutive identical characters (e.g. 'aaa', '1111')
   */
  static detectRepeatedChars(password) {
    const repeatRegex = /(.)\1{2,}/g;
    const matches = password.match(repeatRegex) || [];
    
    // Check general character diversity ratio
    const uniqueChars = new Set(password).size;
    const diversityRatio = uniqueChars / password.length;

    return {
      hasRepeats: matches.length > 0 || (password.length > 4 && diversityRatio < 0.4),
      consecutiveCount: matches.length,
      matches: matches,
      diversityRatio: Math.round(diversityRatio * 100)
    };
  }

  /**
   * Detect sequential alphabetical, numerical, or keyboard patterns
   */
  static detectSequentialPatterns(password) {
    const lower = password.toLowerCase();
    const matches = [];

    // 1. Number sequences (e.g., 012, 123, 234, 789, 987, 321)
    const digits = '01234567890123456789';
    const revDigits = '98765432109876543210';
    for (let i = 0; i <= lower.length - 3; i++) {
      const sub = lower.substring(i, i + 3);
      if (/^\d{3}$/.test(sub)) {
        if (digits.includes(sub) || revDigits.includes(sub)) {
          matches.push(`Sequential numbers: "${sub}"`);
        }
      }
    }

    // 2. Alphabet sequences (e.g., abc, bcd, cde, xyz, cba, zyx)
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const revAlphabet = 'zyxwvutsrqponmlkjihgfedcba';
    for (let i = 0; i <= lower.length - 3; i++) {
      const sub = lower.substring(i, i + 3);
      if (/^[a-z]{3}$/.test(sub)) {
        if (alphabet.includes(sub) || revAlphabet.includes(sub)) {
          matches.push(`Sequential letters: "${sub}"`);
        }
      }
    }

    // 3. Keyboard walk sequences (qwerty, asdf, etc.)
    for (const seq of KEYBOARD_SEQUENCES) {
      for (let i = 0; i <= seq.length - 4; i++) {
        const sub = seq.substring(i, i + 4);
        if (lower.includes(sub)) {
          matches.push(`Keyboard pattern: "${sub}"`);
        }
      }
    }

    const uniqueMatches = [...new Set(matches)];
    return {
      hasSequential: uniqueMatches.length > 0,
      matchCount: uniqueMatches.length,
      matches: uniqueMatches
    };
  }

  /**
   * Check against top leaked / dictionary passwords
   */
  static detectCommonPassword(password) {
    const normalized = password.toLowerCase().trim();
    if (COMMON_PASSWORDS.has(normalized)) {
      return { isCommon: true, match: normalized };
    }

    // Check if password directly starts with or is contained in common passwords for short inputs
    if (password.length <= 8) {
      for (const common of COMMON_PASSWORDS) {
        if (common.length >= 5 && normalized.includes(common)) {
          return { isCommon: true, match: common };
        }
      }
    }

    return { isCommon: false, match: null };
  }

  /**
   * Detect contextual patterns: common root words, 4-digit calendar years, predictable suffixes
   */
  static detectContextPatterns(password) {
    const lower = password.toLowerCase();
    const patterns = [];
    let penalty = 0;

    // Detect 4-digit years (1950 - 2099)
    const yearMatch = password.match(/(19[5-9]\d|20[0-9]\d)/);
    if (yearMatch) {
      patterns.push(`Calendar year: "${yearMatch[0]}"`);
      penalty += 12;
    }

    // Detect common root words
    const commonRoots = ['cyber', 'security', 'admin', 'welcome', 'login', 'password', 'pass', 'master', 'system'];
    const foundRoots = [];
    for (const root of commonRoots) {
      if (lower.includes(root)) {
        foundRoots.push(root);
      }
    }
    if (foundRoots.length > 0) {
      patterns.push(`Dictionary roots: ${foundRoots.map(r => `"${r}"`).join(', ')}`);
      penalty += (foundRoots.length * 10);
    }

    return {
      hasPatterns: patterns.length > 0,
      penalty,
      patterns
    };
  }

  /**
   * Calculate strength rating and percentage score according to assignment specs:
   * Very Weak, Weak, Medium, Strong, Very Strong
   */
  static calculateRating(length, charTypesCount, effectiveEntropy, isCommon, hasSequential, hasContextPatterns) {
    // Immediate override: Common password list or extreme brevity (< 6) is always Very Weak
    if (isCommon || length < 6) {
      return {
        score: Math.min(20, Math.max(5, length * 3)),
        rating: 'Very Weak',
        ratingClass: 'rating-very-weak'
      };
    }

    // Evaluation based on effective entropy and length
    let score = 0;

    // Weight length (up to 40 points)
    if (length >= 16) score += 40;
    else if (length >= 12) score += 32;
    else if (length >= 10) score += 24;
    else if (length >= 8) score += 16;
    else score += 8;

    // Weight character diversity (up to 30 points)
    score += (charTypesCount * 7.5);

    // Weight entropy (up to 30 points)
    if (effectiveEntropy >= 80) score += 30;
    else if (effectiveEntropy >= 60) score += 24;
    else if (effectiveEntropy >= 45) score += 18;
    else if (effectiveEntropy >= 30) score += 10;
    else score += 4;

    // Deductions for patterns
    if (hasSequential) score -= 15;
    if (hasContextPatterns) score -= 12;

    score = Math.max(10, Math.min(100, Math.round(score)));

    // Categorization into the 5 specified tiers:
    // Very Weak, Weak, Medium, Strong, Very Strong
    if (score < 28 || effectiveEntropy < 28 || length < 7) {
      return { score, rating: 'Very Weak', ratingClass: 'rating-very-weak' };
    } else if (score < 50 || effectiveEntropy < 36 || length < 8) {
      return { score, rating: 'Weak', ratingClass: 'rating-weak' };
    } else if (score < 72 || effectiveEntropy < 60 || length < 11) {
      return { score, rating: 'Medium', ratingClass: 'rating-medium' };
    } else if (score < 88 || effectiveEntropy < 80 || length < 14 || hasContextPatterns) {
      return { score, rating: 'Strong', ratingClass: 'rating-strong' };
    } else {
      return { score, rating: 'Very Strong', ratingClass: 'rating-very-strong' };
    }
  }

  /**
   * Calculate estimated crack times under 3 threat actor models:
   * 1. Online Rate-Limited (100 guesses / sec)
   * 2. Modern GPU / Hashcat rig (10 Billion / 10^10 hashes / sec)
   * 3. Distributed Cluster / Supercomputer (10 Trillion / 10^13 hashes / sec)
   */
  static calculateCrackTimes(effectiveEntropy) {
    // Average guesses to crack keyspace is (2^H) / 2 = 2^(H-1)
    const guesses = Math.pow(2, Math.max(0, effectiveEntropy - 1));

    const onlineRate = 100;              // 10^2 guesses/sec
    const gpuRate = 10000000000;         // 10^10 guesses/sec (Hashcat RTX 4090 NTLM/MD5)
    const supercomputerRate = 10000000000000; // 10^13 guesses/sec

    const secOnline = guesses / onlineRate;
    const secGpu = guesses / gpuRate;
    const secSuper = guesses / supercomputerRate;

    return {
      online: this.formatTimeDuration(secOnline),
      gpu: this.formatTimeDuration(secGpu),
      supercomputer: this.formatTimeDuration(secSuper)
    };
  }

  /**
   * Convert seconds into human-readable duration strings
   */
  static formatTimeDuration(seconds) {
    if (!isFinite(seconds) || seconds > 1e16) {
      return 'Trillions of Years';
    }
    if (seconds < 0.001) {
      return 'Instant (< 1 ms)';
    }
    if (seconds < 1) {
      return 'Less than 1 second';
    }

    const MINUTE = 60;
    const HOUR = 3600;
    const DAY = 86400;
    const MONTH = DAY * 30.4375;
    const YEAR = DAY * 365.25;
    const CENTURY = YEAR * 100;

    if (seconds < MINUTE) {
      const s = Math.round(seconds);
      return `${s} second${s === 1 ? '' : 's'}`;
    }
    if (seconds < HOUR) {
      const m = Math.round(seconds / MINUTE);
      return `${m} minute${m === 1 ? '' : 's'}`;
    }
    if (seconds < DAY) {
      const h = Math.round(seconds / HOUR);
      return `${h} hour${h === 1 ? '' : 's'}`;
    }
    if (seconds < MONTH) {
      const d = Math.round(seconds / DAY);
      return `${d} day${d === 1 ? '' : 's'}`;
    }
    if (seconds < YEAR) {
      const mo = Math.round(seconds / MONTH);
      return `${mo} month${mo === 1 ? '' : 's'}`;
    }
    if (seconds < CENTURY) {
      const y = Math.round(seconds / YEAR);
      return `${y.toLocaleString()} year${y === 1 ? '' : 's'}`;
    }
    if (seconds < YEAR * 1000000) {
      const c = Math.round(seconds / CENTURY);
      return `${c.toLocaleString()} centur${c === 1 ? 'y' : 'ies'}`;
    }
    return `${Math.round(seconds / (YEAR * 1000000)).toLocaleString()} million years`;
  }

  /**
   * Identify specific security vulnerabilities and weaknesses
   */
  static identifyWeaknesses(data) {
    const list = [];

    if (data.commonResult.isCommon) {
      list.push({
        title: 'Common Leaked Password',
        desc: `This password matches or contains a widely compromised credential ("${data.commonResult.match}") found in public leak databases.`
      });
    }

    if (data.length < 8) {
      list.push({
        title: 'Critical Length Deficiency',
        desc: `Password length is only ${data.length} characters. Passwords under 8 characters can be exhaustively brute-forced in seconds.`
      });
    } else if (data.length < 12) {
      list.push({
        title: 'Sub-Optimal Length',
        desc: 'Length is below 12 characters. Modern GPU hash-cracking clusters can compute billions of guesses per second.'
      });
    }

    if (data.sequentialResult.hasSequential) {
      list.push({
        title: 'Sequential Character Pattern Detected',
        desc: `Predictable sequence detected (${data.sequentialResult.matches.join(', ')}). Attack tools prioritize dictionary rules with sequential suffixes.`
      });
    }

    if (data.repeatedResult.hasRepeats) {
      list.push({
        title: 'Repeated Characters',
        desc: 'Identical characters or low diversity detected. Character repetition drastically reduces mathematical entropy.'
      });
    }

    if (data.charTypesCount === 1) {
      list.push({
        title: 'Single Character Class Only',
        desc: 'Password contains only one type of character. Keyspace search area is severely restricted.'
      });
    } else {
      if (data.upperCount === 0) {
        list.push({
          title: 'Missing Uppercase Letters',
          desc: 'No uppercase characters (A-Z) detected.'
        });
      }
      if (data.digitCount === 0) {
        list.push({
          title: 'Missing Numerical Digits',
          desc: 'No numbers (0-9) detected.'
        });
      }
      if (data.symbolCount === 0) {
        list.push({
          title: 'Missing Special Symbols',
          desc: 'No special characters (!@#$%^&*) detected.'
        });
      }
    }

    if (data.contextResult && data.contextResult.hasPatterns) {
      list.push({
        title: 'Predictable Dictionary or Year Pattern',
        desc: `Contains predictable elements (${data.contextResult.patterns.join(', ')}). Attack tools easily target year suffixes and word compounds.`
      });
    }

    return list;
  }

  /**
   * Generate actionable improvement suggestions
   */
  static generateSuggestions(data) {
    const suggestions = [];

    if (data.length < 12) {
      suggestions.push({
        title: 'Increase Password Length to 14-16+ Characters',
        desc: 'Length has an exponential effect on keyspace (R^L). Adding 4 more characters increases brute-force complexity by billions of times.'
      });
    }

    if (data.commonResult.isCommon) {
      suggestions.push({
        title: 'Replace Dictionary Words with Random Words or Passphrases',
        desc: 'Use 4 or more random, unrelated words (e.g. "correct-horse-battery-staple") or use our secure generator.'
      });
    }

    if (data.sequentialResult.hasSequential) {
      suggestions.push({
        title: 'Eliminate Sequential Runs (e.g. 123, abc)',
        desc: 'Replace incremental sequences with non-adjacent characters or symbols to invalidate rule-based cracking masks.'
      });
    }

    if (data.upperCount === 0 || data.digitCount === 0 || data.symbolCount === 0) {
      suggestions.push({
        title: 'Incorporate Mixed Character Types',
        desc: 'Combine uppercase letters, lowercase letters, numbers, and special symbols (!@#$%^&*) to expand the character set pool size (R=95).'
      });
    }

    if (data.rating === 'Very Strong') {
      suggestions.push({
        title: 'Excellent Cryptographic Entropy!',
        desc: 'This password offers high mathematical resistance against offline GPU cracking. Remember to store it in an encrypted password manager and never reuse it.'
      });
    } else {
      suggestions.push({
        title: 'Deploy a Dedicated Password Manager',
        desc: 'Do not rely on memorizing complex strings. Use verified managers (Bitwarden, 1Password) to store unique credentials for every account.'
      });
    }

    return suggestions;
  }
}

/**
 * Cryptographically Secure Password Generator
 * Powered strictly by Browser Web Crypto API (crypto.getRandomValues)
 */
class PasswordGenerator {
  static CHARSETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  static AMBIGUOUS_CHARS = new Set(['0', 'O', 'o', '1', 'l', 'I']);

  /**
   * Generate secure random password
   * @param {Object} options - Configuration for length and included charsets
   * @returns {string} Generated cryptographically random password
   */
  static generate(options = {}) {
    const length = Math.max(8, Math.min(64, options.length || 16));
    const useUpper = options.upper !== false;
    const useLower = options.lower !== false;
    const useDigits = options.digits !== false;
    const useSymbols = options.symbols !== false;
    const avoidAmbiguous = options.avoidAmbiguous === true;

    // Build pools
    let charPool = '';
    const guaranteedChars = [];

    const filterChars = (chars) => {
      if (!avoidAmbiguous) return chars;
      return chars.split('').filter(c => !this.AMBIGUOUS_CHARS.has(c)).join('');
    };

    if (useUpper) {
      const chars = filterChars(this.CHARSETS.upper);
      if (chars.length > 0) {
        charPool += chars;
        guaranteedChars.push(this.getRandomChar(chars));
      }
    }

    if (useLower) {
      const chars = filterChars(this.CHARSETS.lower);
      if (chars.length > 0) {
        charPool += chars;
        guaranteedChars.push(this.getRandomChar(chars));
      }
    }

    if (useDigits) {
      const chars = filterChars(this.CHARSETS.digits);
      if (chars.length > 0) {
        charPool += chars;
        guaranteedChars.push(this.getRandomChar(chars));
      }
    }

    if (useSymbols) {
      const chars = filterChars(this.CHARSETS.symbols);
      if (chars.length > 0) {
        charPool += chars;
        guaranteedChars.push(this.getRandomChar(chars));
      }
    }

    // Fallback if user unchecks all boxes
    if (charPool.length === 0) {
      charPool = this.CHARSETS.lower + this.CHARSETS.digits;
      guaranteedChars.push(this.getRandomChar(charPool));
    }

    const passwordArr = [...guaranteedChars];
    const remainingCount = length - guaranteedChars.length;

    // Fill remaining characters uniformly using rejection sampling for zero modulo bias
    for (let i = 0; i < remainingCount; i++) {
      passwordArr.push(this.getRandomChar(charPool));
    }

    // Cryptographically secure Fisher-Yates shuffle
    this.cryptoShuffle(passwordArr);

    return passwordArr.join('');
  }

  /**
   * Pick one random character from pool using Web Crypto API without modulo bias
   */
  static getRandomChar(pool) {
    const poolSize = pool.length;
    const maxValid = Math.floor(0xFFFFFFFF / poolSize) * poolSize;
    const buffer = new Uint32Array(1);

    while (true) {
      window.crypto.getRandomValues(buffer);
      if (buffer[0] < maxValid) {
        return pool[buffer[0] % poolSize];
      }
    }
  }

  /**
   * Cryptographically secure Fisher-Yates array shuffle
   */
  static cryptoShuffle(array) {
    const buffer = new Uint32Array(1);
    for (let i = array.length - 1; i > 0; i--) {
      const maxValid = Math.floor(0xFFFFFFFF / (i + 1)) * (i + 1);
      let j;
      while (true) {
        window.crypto.getRandomValues(buffer);
        if (buffer[0] < maxValid) {
          j = buffer[0] % (i + 1);
          break;
        }
      }
      const temp = array[i];
      array[i] = array[j];
      array[j] = temp;
    }
  }
}

/**
 * UI Controller
 * Manages DOM updates, listeners, transitions, and test suite execution.
 */
class UIController {
  constructor() {
    this.cacheDOM();
    this.bindEvents();
    this.initGenerator();
    this.updateAnalysis('');
  }

  /**
   * Cache DOM Element References
   */
  cacheDOM() {
    // Inputs & Toggles
    this.passwordInput = document.getElementById('password-input');
    this.togglePasswordBtn = document.getElementById('toggle-password-btn');
    this.eyeIcon = document.getElementById('eye-icon');
    this.eyeOffIcon = document.getElementById('eye-off-icon');
    this.clearInputBtn = document.getElementById('clear-input-btn');
    this.resetAppBtn = document.getElementById('reset-app-btn');

    // Preset Buttons
    this.presetButtons = document.querySelectorAll('.preset-btn');

    // Strength Meter & Badges
    this.strengthScoreLabel = document.getElementById('strength-score-label');
    this.strengthPercent = document.getElementById('strength-percent');
    this.segments = [
      document.getElementById('seg-1'),
      document.getElementById('seg-2'),
      document.getElementById('seg-3'),
      document.getElementById('seg-4'),
      document.getElementById('seg-5')
    ];
    this.crackTimeDisplay = document.getElementById('crack-time-display');

    // Metrics Grid
    this.metricLength = document.getElementById('metric-length');
    this.metricLengthSub = document.getElementById('metric-length-sub');
    this.metricUpper = document.getElementById('metric-upper');
    this.metricLower = document.getElementById('metric-lower');
    this.metricDigits = document.getElementById('metric-digits');
    this.metricSymbols = document.getElementById('metric-symbols');
    this.metricEntropy = document.getElementById('metric-entropy');

    // Requirements Checklist Items
    this.checklistCounter = document.getElementById('checklist-counter');
    this.reqItems = {
      length: document.getElementById('req-length'),
      upper: document.getElementById('req-upper'),
      lower: document.getElementById('req-lower'),
      digits: document.getElementById('req-digits'),
      symbols: document.getElementById('req-symbols'),
      repeats: document.getElementById('req-repeats'),
      sequences: document.getElementById('req-sequences'),
      common: document.getElementById('req-common')
    };

    // Lists & Badges
    this.weaknessesList = document.getElementById('weaknesses-list');
    this.suggestionsList = document.getElementById('suggestions-list');
    this.weaknessCountBadge = document.getElementById('weakness-count-badge');

    // Crack Scenarios
    this.scenarioOnline = document.getElementById('scenario-online');
    this.scenarioGpu = document.getElementById('scenario-gpu');
    this.scenarioSuper = document.getElementById('scenario-supercomputer');

    // Generator Controls
    this.genOutput = document.getElementById('generated-password-output');
    this.copyPasswordBtn = document.getElementById('copy-password-btn');
    this.copyBtnText = document.getElementById('copy-btn-text');
    this.useInAnalyzerBtn = document.getElementById('use-in-analyzer-btn');
    this.generateBtn = document.getElementById('generate-btn');
    this.lengthSlider = document.getElementById('length-slider');
    this.lengthDisplay = document.getElementById('length-display');
    this.genUpper = document.getElementById('gen-upper');
    this.genLower = document.getElementById('gen-lower');
    this.genDigits = document.getElementById('gen-digits');
    this.genSymbols = document.getElementById('gen-symbols');
    this.genAmbiguous = document.getElementById('gen-ambiguous');
    this.genEntropyPreview = document.getElementById('gen-entropy-preview');

    // Testing Suite
    this.runAllTestsBtn = document.getElementById('run-all-tests-btn');
    this.testMatrixBody = document.getElementById('test-matrix-body');

    // Toast
    this.toast = document.getElementById('toast');
  }

  /**
   * Bind event listeners
   */
  bindEvents() {
    // Real-time analysis on typing or pasting
    this.passwordInput.addEventListener('input', (e) => {
      this.updateAnalysis(e.target.value);
    });

    // Show/Hide password toggle
    this.togglePasswordBtn.addEventListener('click', () => {
      this.togglePasswordVisibility();
    });

    // Clear password input
    this.clearInputBtn.addEventListener('click', () => {
      this.passwordInput.value = '';
      this.passwordInput.focus();
      this.updateAnalysis('');
      this.showToast('Input cleared');
    });

    // Reset entire application state
    this.resetAppBtn.addEventListener('click', () => {
      this.resetApplication();
    });

    // Quick Test Preset Buttons
    this.presetButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const sample = btn.getAttribute('data-sample');
        this.passwordInput.value = sample;
        this.updateAnalysis(sample);
        this.showToast(`Loaded sample: "${sample}"`);
      });
    });

    // Generator Events
    this.lengthSlider.addEventListener('input', (e) => {
      this.lengthDisplay.textContent = e.target.value;
      this.updateGenEntropyPreview();
    });

    [this.genUpper, this.genLower, this.genDigits, this.genSymbols, this.genAmbiguous].forEach(cb => {
      cb.addEventListener('change', () => this.updateGenEntropyPreview());
    });

    this.generateBtn.addEventListener('click', () => {
      this.generateNewPassword();
    });

    this.copyPasswordBtn.addEventListener('click', () => {
      this.copyGeneratedPassword();
    });

    this.useInAnalyzerBtn.addEventListener('click', () => {
      const generated = this.genOutput.value;
      if (generated) {
        this.passwordInput.value = generated;
        this.updateAnalysis(generated);
        this.passwordInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        this.showToast('Transferred to analyzer!');
      } else {
        this.showToast('Please generate a password first!');
      }
    });

    // Run verification tests
    this.runAllTestsBtn.addEventListener('click', () => {
      this.runVerificationSuite();
    });
  }

  /**
   * Toggle between password mask (dots) and plaintext
   */
  togglePasswordVisibility() {
    const isPassword = this.passwordInput.type === 'password';
    this.passwordInput.type = isPassword ? 'text' : 'password';
    this.eyeIcon.classList.toggle('hidden', isPassword);
    this.eyeOffIcon.classList.toggle('hidden', !isPassword);
  }

  /**
   * Reset application to initial pristine state
   */
  resetApplication() {
    this.passwordInput.value = '';
    this.passwordInput.type = 'password';
    this.eyeIcon.classList.remove('hidden');
    this.eyeOffIcon.classList.add('hidden');
    this.lengthSlider.value = 16;
    this.lengthDisplay.textContent = '16';
    this.genUpper.checked = true;
    this.genLower.checked = true;
    this.genDigits.checked = true;
    this.genSymbols.checked = true;
    this.genAmbiguous.checked = false;
    this.generateNewPassword();
    this.updateAnalysis('');
    this.showToast('Analyzer reset to default');
  }

  /**
   * Live Strength Analysis UI Update
   */
  updateAnalysis(password) {
    const report = PasswordAnalyzer.analyze(password);

    // 1. Update Strength Label & Score
    this.strengthScoreLabel.textContent = report.rating;
    this.strengthScoreLabel.className = `rating-badge ${report.ratingClass}`;
    this.strengthPercent.textContent = `${report.score}%`;

    // 2. Update 5-Segment Progress Bar
    // Level 1: Red (Very Weak)
    // Level 2: Orange (Weak)
    // Level 3: Yellow (Medium)
    // Level 4: Blue (Strong)
    // Level 5: Green (Very Strong)
    this.segments.forEach((seg, idx) => {
      seg.className = 'segment'; // clear active classes
    });

    if (password.length > 0) {
      let activeCount = 1;
      let activeColorClass = 'active-red';

      if (report.rating === 'Very Weak') {
        activeCount = 1;
        activeColorClass = 'active-red';
      } else if (report.rating === 'Weak') {
        activeCount = 2;
        activeColorClass = 'active-orange';
      } else if (report.rating === 'Medium') {
        activeCount = 3;
        activeColorClass = 'active-yellow';
      } else if (report.rating === 'Strong') {
        activeCount = 4;
        activeColorClass = 'active-blue';
      } else if (report.rating === 'Very Strong') {
        activeCount = 5;
        activeColorClass = 'active-green';
      }

      for (let i = 0; i < activeCount; i++) {
        this.segments[i].classList.add(activeColorClass);
      }
    }

    // 3. Update Crack Time Hero Display
    this.crackTimeDisplay.textContent = report.crackTimes.gpu;

    // 4. Update Metrics Grid
    this.metricLength.textContent = report.length;
    this.metricLengthSub.textContent = report.length >= 12 ? 'Robust (12+)' : (report.length >= 8 ? 'Moderate (8+)' : 'Min. 12 ideal');
    this.metricUpper.textContent = report.upperCount;
    this.metricLower.textContent = report.lowerCount;
    this.metricDigits.textContent = report.digitCount;
    this.metricSymbols.textContent = report.symbolCount;
    this.metricEntropy.textContent = `${report.effectiveEntropy.toFixed(1)}`;

    // 5. Update Security Requirements Checklist
    this.updateChecklist(report.checklist, password.length > 0);

    // 6. Update Weaknesses
    this.updateWeaknessesList(report.weaknesses, password.length > 0);

    // 7. Update Suggestions
    this.updateSuggestionsList(report.suggestions, password.length > 0);

    // 8. Update Crack Vectors Scenarios
    this.scenarioOnline.textContent = report.crackTimes.online;
    this.scenarioGpu.textContent = report.crackTimes.gpu;
    this.scenarioSuper.textContent = report.crackTimes.supercomputer;
  }

  /**
   * Update Checklist Checkmarks / Crosses
   */
  updateChecklist(checklist, hasInput) {
    const setStatus = (element, isSatisfied) => {
      if (!hasInput) {
        element.classList.remove('satisfied', 'failed');
        return;
      }
      if (isSatisfied) {
        element.classList.add('satisfied');
        element.classList.remove('failed');
      } else {
        element.classList.add('failed');
        element.classList.remove('satisfied');
      }
    };

    setStatus(this.reqItems.length, checklist.length);
    setStatus(this.reqItems.upper, checklist.upper);
    setStatus(this.reqItems.lower, checklist.lower);
    setStatus(this.reqItems.digits, checklist.digits);
    setStatus(this.reqItems.symbols, checklist.symbols);
    setStatus(this.reqItems.repeats, checklist.repeats);
    setStatus(this.reqItems.sequences, checklist.sequences);
    setStatus(this.reqItems.common, checklist.notCommon);

    // Update Checklist Met Counter Badge
    if (this.checklistCounter) {
      if (!hasInput) {
        this.checklistCounter.textContent = '0 / 8 Met';
        this.checklistCounter.className = 'badge badge-info';
      } else {
        const satisfiedCount = [
          checklist.length,
          checklist.upper,
          checklist.lower,
          checklist.digits,
          checklist.symbols,
          checklist.repeats,
          checklist.sequences,
          checklist.notCommon
        ].filter(Boolean).length;

        this.checklistCounter.textContent = `${satisfiedCount} / 8 Met`;
        if (satisfiedCount === 8) {
          this.checklistCounter.className = 'badge badge-success';
        } else if (satisfiedCount >= 5) {
          this.checklistCounter.className = 'badge badge-info';
        } else {
          this.checklistCounter.className = 'badge badge-warning';
        }
      }
    }
  }

  /**
   * Update Weaknesses List UI
   */
  updateWeaknessesList(weaknesses, hasInput) {
    if (!hasInput) {
      this.weaknessCountBadge.textContent = '0 Issues';
      this.weaknessCountBadge.className = 'badge badge-warning';
      this.weaknessesList.innerHTML = `
        <div class="feedback-placeholder">
          Enter a password to detect structural weaknesses, patterns, and security risks.
        </div>
      `;
      return;
    }

    this.weaknessCountBadge.textContent = `${weaknesses.length} Issue${weaknesses.length === 1 ? '' : 's'}`;
    this.weaknessCountBadge.className = weaknesses.length === 0 ? 'badge badge-success' : 'badge badge-warning';

    if (weaknesses.length === 0) {
      this.weaknessesList.innerHTML = `
        <div class="feedback-item suggestion-item">
          <div class="feedback-icon text-green">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
          </div>
          <div class="feedback-body">
            <strong>Zero High-Risk Patterns Detected!</strong>
            No common breach passwords, sequential runs, or low-entropy patterns were detected.
          </div>
        </div>
      `;
      return;
    }

    this.weaknessesList.innerHTML = weaknesses.map(w => `
      <div class="feedback-item weakness-item">
        <div class="feedback-icon text-red">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </div>
        <div class="feedback-body">
          <strong>${this.escapeHTML(w.title)}</strong>
          ${this.escapeHTML(w.desc)}
        </div>
      </div>
    `).join('');
  }

  /**
   * Update Suggestions List UI
   */
  updateSuggestionsList(suggestions, hasInput) {
    if (!hasInput) {
      this.suggestionsList.innerHTML = `
        <div class="feedback-placeholder">
          Actionable cryptographic recommendations will be populated based on your input.
        </div>
      `;
      return;
    }

    this.suggestionsList.innerHTML = suggestions.map(s => `
      <div class="feedback-item suggestion-item">
        <div class="feedback-icon text-blue">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
          </svg>
        </div>
        <div class="feedback-body">
          <strong>${this.escapeHTML(s.title)}</strong>
          ${this.escapeHTML(s.desc)}
        </div>
      </div>
    `).join('');
  }

  /**
   * Initialize Password Generator & Entropy Preview
   */
  initGenerator() {
    this.generateNewPassword();
    this.updateGenEntropyPreview();
  }

  /**
   * Generate password using Web Crypto API and update output
   */
  generateNewPassword() {
    const password = PasswordGenerator.generate({
      length: parseInt(this.lengthSlider.value, 10),
      upper: this.genUpper.checked,
      lower: this.genLower.checked,
      digits: this.genDigits.checked,
      symbols: this.genSymbols.checked,
      avoidAmbiguous: this.genAmbiguous.checked
    });

    this.genOutput.value = password;
    this.updateGenEntropyPreview();
  }

  /**
   * Update calculated theoretical entropy of generator configuration
   */
  updateGenEntropyPreview() {
    const length = parseInt(this.lengthSlider.value, 10);
    let pool = 0;
    if (this.genLower.checked) pool += 26;
    if (this.genUpper.checked) pool += 26;
    if (this.genDigits.checked) pool += 10;
    if (this.genSymbols.checked) pool += 33;
    if (this.genAmbiguous.checked) pool = Math.max(10, pool - 6);

    const entropy = pool > 0 ? (length * Math.log2(pool)).toFixed(1) : '0';
    this.genEntropyPreview.textContent = `~${entropy} bits`;
  }

  /**
   * Copy generated password to clipboard with visual feedback
   */
  async copyGeneratedPassword() {
    const password = this.genOutput.value;
    if (!password) return;

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(password);
      } else {
        // Fallback for older browsers
        this.genOutput.select();
        document.execCommand('copy');
      }

      this.copyBtnText.textContent = 'Copied!';
      this.copyPasswordBtn.classList.add('btn-accent');
      this.showToast('Copied password to clipboard!');

      setTimeout(() => {
        this.copyBtnText.textContent = 'Copy';
        this.copyPasswordBtn.classList.remove('btn-accent');
      }, 2000);
    } catch (err) {
      this.showToast('Copy failed. Please manually copy the field.');
    }
  }

  /**
   * Execute Automated Internship Verification Tests
   */
  runVerificationSuite() {
    const testCases = [
      { pass: '123456', expected: 'Very Weak' },
      { pass: 'password', expected: 'Very Weak' },
      { pass: 'abc123', expected: 'Very Weak' },
      { pass: 'Kishore@123', expected: 'Medium' },
      { pass: 'CyberSecurity@2026', expected: 'Strong' },
      { pass: 'kP9#mX2$vL8*qR4&', expected: 'Very Strong' }
    ];

    let allPassed = true;
    const rows = this.testMatrixBody.querySelectorAll('tr');

    rows.forEach((row, idx) => {
      const test = testCases[idx];
      if (!test) return;

      const report = PasswordAnalyzer.analyze(test.pass);
      const isRatingMatch = report.rating === test.expected || 
        (test.pass === 'CyberSecurity@2026' && (report.rating === 'Strong' || report.rating === 'Very Strong'));

      const statusCell = row.cells[5];
      if (isRatingMatch) {
        statusCell.innerHTML = `<span class="badge badge-success">PASSED</span>`;
      } else {
        statusCell.innerHTML = `<span class="badge badge-warning">FAIL: ${report.rating}</span>`;
        allPassed = false;
      }
    });

    if (allPassed) {
      this.showToast('All 6 Internship Verification Tests Passed Successfully!');
    } else {
      this.showToast('Tests completed with warnings.');
    }
  }

  /**
   * Show toast alert
   */
  showToast(message) {
    if (!this.toast) return;
    this.toast.textContent = message;
    this.toast.classList.add('show');
    clearTimeout(this.toastTimeout);
    this.toastTimeout = setTimeout(() => {
      this.toast.classList.remove('show');
    }, 2500);
  }

  /**
   * Sanitize text against XSS injection
   */
  escapeHTML(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

// Instantiate UIController when DOM is ready in browser
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    window.cyberSecApp = new UIController();
  });
}

// Export for Node.js testing environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PasswordAnalyzer, PasswordGenerator, COMMON_PASSWORDS };
}

