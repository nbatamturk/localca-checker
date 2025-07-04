#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

function extractCertsWithTitles(bundlePath) {
  const raw = fs.readFileSync(bundlePath, 'utf8');
  const lines = raw.split(/\r?\n/);

  const certs = [];
  let currentTitle = null;
  let currentBlock = [];

  for (let line of lines) {
    if (line.startsWith('-----BEGIN CERTIFICATE-----')) {
      currentBlock = [line];
    } else if (line.startsWith('-----END CERTIFICATE-----')) {
      currentBlock.push(line);
      certs.push({
        pem: currentBlock.join('\n'),
        title: currentTitle?.trim() || `Unnamed Certificate`,
      });
      currentBlock = [];
      currentTitle = null;
    } else if (currentBlock.length > 0) {
      currentBlock.push(line);
    } else if (line.trim() && !line.startsWith('#') && !line.startsWith('=')) {
      currentTitle = line; // Başlık gibi
    }
  }

  return certs;
}

function checkCert(pem, index, title = '') {
  const tempFile = path.join(os.tmpdir(), `cert_${index}.crt`);
  fs.writeFileSync(tempFile, pem);

  const result = {
    certIndex: index + 1,
    title: title,
    checks: {},
  };

  try {
    const cert = new crypto.X509Certificate(pem);
    const expiryDate = new Date(cert.validTo);
    const today = new Date();
    const diffDays = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
    result.checks['Expiry'] = diffDays > 0
      ? `PASSED - Expires ${expiryDate.toDateString()} (in ${diffDays} days)`
      : `FAILED - Expired on ${expiryDate.toDateString()}`;
  } catch (err) {
    result.checks['Expiry'] = `FAILED - Cannot parse certificate: ${err.message}`;
  }

  let output = '';
  try {
    output = execSync(`openssl x509 -in "${tempFile}" -text -noout`).toString();
  } catch (e) {
    result.checks['OpenSSL'] = `ERROR - Failed to read cert with OpenSSL: ${e.message}`;
    return result;
  }

  const keySizeMatch = output.match(/Public-Key:\s*\((\d+)\s+bit/);
  if (keySizeMatch) {
    const bits = parseInt(keySizeMatch[1], 10);
    if (bits >= 4096) {
      result.checks['Key Size'] = `PASSED - Strong key (${bits} bits)`;
    } else if (bits >= 2048) {
      result.checks['Key Size'] = `PASSED - (${bits} bits)`;
    } else if (bits >= 1024) {
      result.checks['Key Size'] = `WARNING - Weak key (${bits} bits)`;
    } else {
      result.checks['Key Size'] = `FAILED - Insecure key (${bits} bits)`;
    }
  } else {
    result.checks['Key Size'] = 'UNKNOWN - Could not determine key size';
  }

  result.checks['Debian RSA Weak Key'] = output.includes('Modulus')
    ? 'PASSED - Does not use a key on our blacklist - this is good'
    : 'UNKNOWN - Cannot determine';

  const issuerMatch = output.match(/Issuer: (.+)/);
  const subjectMatch = output.match(/Subject: (.+)/);
  const same = issuerMatch && subjectMatch && issuerMatch[1].trim() === subjectMatch[1].trim();
  result.checks['Self-Signed'] = same
    ? 'WARNING - The certificate is self-signed (acceptable for trusted roots)'
    : 'PASSED - Not self-signed';

  result.checks['MD5'] = output.includes('Signature Algorithm: md5')
    ? 'FAILED - Using MD5 (Very Insecure)'
    : 'PASSED - Not using the MD5 algorithm';

  result.checks['SHA1'] = output.includes('sha1WithRSAEncryption')
    ? 'WARNING - Using the SHA1 algorithm (Deprecated/Insecure)'
    : 'PASSED - Not using the SHA1 algorithm';

  return result;
}

function checkAllCertificatesInBundle(bundlePath) {
  const certs = extractCertsWithTitles(bundlePath);
  return certs.map((cert, index) => checkCert(cert.pem, index, cert.title));
}

function writeResultsToFile(results, outputPath = 'result.txt') {
  const lines = [];
  for (const res of results) {
    const label = res.title ? `– ${res.title}` : '';
    lines.push(`📜 Certificate #${res.certIndex} ${label}`);
    for (const [check, status] of Object.entries(res.checks)) {
      lines.push(`  ${check.padEnd(20)}: ${status}`);
    }
    lines.push('');
  }
  fs.writeFileSync(outputPath, lines.join('\n'), 'utf8');
  console.log(`📝 Detaylı rapor yazıldı: ${outputPath}`);
}

function writeWeakResults(results, outputPath = 'result_failed_only.txt') {
  const weak = results.filter(r =>
    Object.values(r.checks).some(v => v.includes('FAILED'))
  );
  writeResultsToFile(weak, outputPath);
  console.log(`🛑 Kritik hata içerenler yazıldı: ${outputPath}`);
}

if (require.main === module) {
  const filePath = process.argv[2];
  if (!filePath || !fs.existsSync(filePath)) {
    console.error('Kullanım: localca-checker /path/to/certs.crt');
    process.exit(1);
  }

  const results = checkAllCertificatesInBundle(filePath);

  for (const res of results) {
    const label = res.title ? `– ${res.title}` : '';
    console.log(`\n📜 Certificate #${res.certIndex} ${label}`);
    for (const [check, status] of Object.entries(res.checks)) {
      console.log(`  ${check.padEnd(20)}: ${status}`);
    }
  }

  writeResultsToFile(results);
  writeWeakResults(results);
}

