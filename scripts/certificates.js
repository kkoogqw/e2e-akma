const forge = require('node-forge');
const fs = require('fs');

function generatePKICertificate(name) {
    // Create a key pair (public and private keys)
    const keys = forge.pki.rsa.generateKeyPair(4096);

    // Create a new certificate
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1); // 1-year validity

    // Set certificate attributes (subject and issuer)
    const attrs = [
        { name: 'commonName', value: 'ppakma.com' },
        { name: 'countryName', value: 'CN' },
        { shortName: 'ST', value: 'Beijing' },
        { name: 'localityName', value: 'Beijing' },
        { name: 'organizationName', value: `PP-AKMA ${name}` },
        { shortName: 'OU', value: 'IT' }
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Self-sign the certificate
    cert.sign(keys.privateKey, forge.md.sha256.create());

    // Convert the certificate and private key to PEM format
    const pemCert = forge.pki.certificateToPem(cert);
    const pemPrivateKey = forge.pki.privateKeyToPem(keys.privateKey);
    const pemPublicKey = forge.pki.publicKeyToPem(keys.publicKey);

    // Output the PEM-formatted certificate and keys
    console.log("Certificate:\n", pemCert);
    console.log("Private Key:\n", pemPrivateKey);
    console.log("Public Key:\n", pemPublicKey);

    fs.writeFileSync(`./certs/${name}.pem`, pemCert);
    fs.writeFileSync(`./certs/${name}.priv.key`, pemPrivateKey);
    fs.writeFileSync(`./certs/${name}.pub.key`, pemPublicKey);


    return { pemCert, pemPrivateKey, pemPublicKey };
}

// Generate the certificate and log the result
generatePKICertificate("AF-DEMO");
