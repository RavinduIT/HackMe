import forge from 'node-forge';
import fs from 'fs';
import path from 'path';
import { app } from 'electron';

const certCache = new Map<string, { cert: string; key: string }>();

let caCert: forge.pki.Certificate | null = null;
let caKey: forge.pki.PrivateKey | null = null;

function getCertDir(): string {
  const dir = path.join(app.getPath('userData'), 'certs');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

export function getOrCreateCA(): { cert: forge.pki.Certificate; key: forge.pki.PrivateKey } {
  if (caCert && caKey) return { cert: caCert, key: caKey };

  const certDir = getCertDir();
  const caCertPath = path.join(certDir, 'hackme-ca.pem');
  const caKeyPath = path.join(certDir, 'hackme-ca-key.pem');

  if (fs.existsSync(caCertPath) && fs.existsSync(caKeyPath)) {
    caCert = forge.pki.certificateFromPem(fs.readFileSync(caCertPath, 'utf8'));
    caKey = forge.pki.privateKeyFromPem(fs.readFileSync(caKeyPath, 'utf8'));
    return { cert: caCert, key: caKey };
  }

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: 'HackMe Security Scanner CA' },
    { name: 'organizationName', value: 'HackMe' },
    { name: 'countryName', value: 'LK' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  fs.writeFileSync(caCertPath, forge.pki.certificateToPem(cert));
  fs.writeFileSync(caKeyPath, forge.pki.privateKeyToPem(keys.privateKey));

  caCert = cert;
  caKey = keys.privateKey;
  return { cert, key: keys.privateKey };
}

export function generateHostCert(hostname: string): { cert: string; key: string } {
  const cached = certCache.get(hostname);
  if (cached) return cached;

  const ca = getOrCreateCA();
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
  ]);

  cert.sign(ca.key as any, forge.md.sha256.create());

  const result = {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };

  certCache.set(hostname, result);
  return result;
}

export function exportCACert(outputPath: string): boolean {
  const ca = getOrCreateCA();
  fs.writeFileSync(outputPath, forge.pki.certificateToPem(ca.cert));
  return true;
}

export function getCACertPath(): string {
  const certDir = getCertDir();
  return path.join(certDir, 'hackme-ca.pem');
}
