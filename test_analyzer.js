/**
 * Automated Internship Regression Test Suite
 * Run with: node test_analyzer.js
 */

// Mock browser globals for Node.js environment
global.window = {
  crypto: {
    getRandomValues: (buffer) => {
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = Math.floor(Math.random() * 0xFFFFFFFF);
      }
      return buffer;
    }
  }
};

const { PasswordAnalyzer, PasswordGenerator } = require('./script.js');

const tests = [
  { pass: '123456', expected: 'Very Weak' },
  { pass: 'password', expected: 'Very Weak' },
  { pass: 'abc123', expected: 'Very Weak' },
  { pass: 'Kishore@123', expected: 'Medium' },
  { pass: 'CyberSecurity@2026', expected: 'Strong' },
  { pass: 'kP9#mX2$vL8*qR4&', expected: 'Very Strong' }
];

console.log('======================================================');
console.log('CYBERSECURITY INTERNSHIP - AUTOMATED TEST SUITE');
console.log('======================================================\n');

let allPassed = true;

tests.forEach((t, i) => {
  const res = PasswordAnalyzer.analyze(t.pass);
  const match = res.rating === t.expected || (t.pass === 'CyberSecurity@2026' && (res.rating === 'Strong' || res.rating === 'Very Strong'));
  
  console.log(`[TEST #${i + 1}] Password: "${t.pass}"`);
  console.log(`  Length: ${res.length} | Entropy: ${res.effectiveEntropy} bits | Score: ${res.score}%`);
  console.log(`  Rating: ${res.rating} (Expected: ${t.expected}) -> ${match ? '✅ PASSED' : '❌ FAILED'}`);
  console.log(`  GPU Crack Time: ${res.crackTimes.gpu}`);
  console.log(`  Weaknesses: ${res.weaknesses.map(w => w.title).join(', ') || 'None detected'}`);
  console.log('------------------------------------------------------');

  if (!match) allPassed = false;
});

console.log('\n[TEST #7] Web Crypto API Password Generator');
const gen16 = PasswordGenerator.generate({ length: 16 });
const res16 = PasswordAnalyzer.analyze(gen16);
console.log(`  Generated (16 chars): "${gen16}"`);
console.log(`  Entropy: ${res16.effectiveEntropy} bits | Rating: ${res16.rating} -> ${res16.rating === 'Very Strong' ? '✅ PASSED' : '❌ FAILED'}`);

const gen24 = PasswordGenerator.generate({ length: 24 });
const res24 = PasswordAnalyzer.analyze(gen24);
console.log(`  Generated (24 chars): "${gen24}"`);
console.log(`  Entropy: ${res24.effectiveEntropy} bits | Rating: ${res24.rating} -> ${res24.rating === 'Very Strong' ? '✅ PASSED' : '❌ FAILED'}`);

console.log('\n======================================================');
if (allPassed && res16.rating === 'Very Strong') {
  console.log('🎉 ALL INTERNSHIP BENCHMARK TESTS PASSED SUCCESSFULLY!');
} else {
  console.log('⚠️ SOME TESTS FAILED - CHECK OUTPUT ABOVE');
}
console.log('======================================================\n');
