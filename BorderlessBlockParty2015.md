# ncdns-tls: Namecoin TLS Authentication for Web Servers

Entry by Jeremy Rand (University of Oklahoma) in the Borderless Block Party Hackathon, November 2015.

## Summary

ncdns-tls uses the Namecoin blockchain-based naming system to verify TLS certificates of web sites without certificate authorities, notaries, or other trusted third parties.  It is built on top of the ncdns DNS server by Hugo Landau, and is coded in Go.  It works by hooking DNS requests for Namecoin (.bit) websites and injects the correct certificate into the trust store, in a way that guarantees that only the certificates in the blockchain for a given domain name will be considered correct for that domain name.

## Feasibility

ncdns-tls is absolutely implementable at a large scale.  The biggest inefficiency in its approach is the use of "dehydrated certificates" (see technical description below), which are larger than simple certificate hashes, but based on the size of the example configuration in the below documentation, if 100,000,000 websites (the approximate number of non-squatted ICANN domains) use it, then the state of the global name database (with pruning of spent and expired names) is 100,000,000 websites * 351 bytes/website = 35.1 GB, which is well within reason.  The other inefficiencies and obstacles in the current implementations are the issues of removing expired certificates, requiring administrator privileges, and supporting browsers that don't use Windows CryptoAPI, but we believe that these are solvable with mild engineering (see the Future Direction sections "Support Other Trust Stores" and "Direct Registry Access to CryptoAPI Trust Store").  If for any reason Namecoin becomes no longer the preferred naming system, ncdns-tls should work (with minimal changes) with other naming systems, such as Ethereum, BitShares, or even systems which use notary trust instead of blockchains (e.g. Perspectives and Convergence for ICANN domains).

## Uniqueness

The idea of using Namecoin to verify TLS certificates has been around since at least 2012, but the idea and ncdns-tls's implementation of injecting certificates into the trust store is new.  Previous approaches either involved intercepting proxies like Convergence (which are high-risk; see SuperFish for an example of what can go wrong), or browser add-ons like DNSSEC-Validator (which leak confidential information when certificate verification fails).  ncdns-tls's use of "dehydrated certificates" (pieces of a certificate which can reconstruct a full certificate deterministically) to sufficiently compress the certificate to fit into a blockchain record (while also making security checks very simple) is also new.  Dehydrated certificates required a fork of the Go standard library's x.509 library, but the changes are very noninvasive.

## Implementation and Execution

ncdns-tls is functional, with an example certificate deployed on https://www.veclabs.bit/ .  There are definitely things that can be improved (see the Future Direction sections below), but the fundamental functionality is proven, working, and deployable (although obviously it should get more review and polishing before being deployed in a situation where security matters).

## Need

The use of certificate authorities (CA's) in TLS is an enormous problem, as disastrous security failures like DigiNotar (in which fraudulent certificates valid for hundreds of providers like Microsoft and Google were issued to an Iranian IP and then deployed for over a month without anyone noticing) make fully clear.  Other proposed solutions like DNSSEC/DANE and notaries (e.g. Perspectives and Convergence) only shift around the trust to what is hoped are slightly more reliable trusted parties.  A fully trust-free TLS validation system with a blockchain security model removes these attack vectors from the equation, which if widely adopted could reduce security risks and costs for businesses and ultimately save the lives of dissidents in repressive countries who rely on TLS to stay safe.

# Additional Documentation

Below is additional documentation for anyone who is interested in learning more, or perhaps running the code.

**Warning: this code is a proof of concept, and has not been subjected to careful testing.  It utilizes specifications which not only are unfinalized, but have not been reviewed by anyone else.  Do not use this code for any public deployments (on either servers or clients) of any kind whatsoever.  We will be working to clean up and standardize this code (and its associated specifications), but we make no guarantees of the timeline associated with said cleanup and standardization.**

## Introduction to Namecoin

Namecoin is a naming system which uses a blockchain.  Namecoin was the first solution to Zooko's Triangle, the long-standing problem of having a naming system which is simultaneously global, decentralized, and human-meaningful.  Namecoin's first use case is the .bit top-level domain, which provides decentralized, global, human-readable DNS.

## Introduction to Namecoin TLS

Websites currently rely on TLS to prove their authenticity.  The TLS certificate authority system is flawed due to centralization.  DNSSEC/DANE does not solve the centralization issue.  Namecoin in theory offers a good solution (by associating TLS certificates with a .bit domain name), but the task of getting mainstream web browsers to accept Namecoin certificates has, so far, remained unsolved.

Existing methods generally either leak private data (e.g. DNSSEC Validator) or rely on intercepting proxies (e.g. Convergence); both of these are deemed insufficiently safe.

## Certificate Injection

We started with the ncdns codebase.  ncdns is a Namecoin authoritative DNS server (in Golang) by Hugo Landau.  We added a callback to ncdns so that when it receives a request for "example.bit" it checks whether a TLSA record exists for "_443._tcp.example.bit".  If such a record exists, it dumps the certificate to a file, and injects it into the local trust store before replying to the DNS request.  This ensures that the web browser will be aware of the certificate prior to beginning certificate validation.

Currently the only trust store which is supported is the Windows CryptoAPI trust store, which is used by Internet Explorer, Chromium/Chrome, and most other Windows software.  Firefox uses NSS instead, which we do not currently support.  OS X and Linux are not supported currently.

## Getting the Certificate

A typical x.509 certificate is often in the range of 2 to 3 KB.  A Namecoin name can only hold 520 bytes, and is often used to store data in addition to TLS authentication data.  In addition, injecting arbitrary certificates into the local trust store is a security risk, because a website might provide a certificate which is valid for another website, or which is usable as a certificate authority.  We solved both of these issues by generating a certificate on the fly of the following form:

1. Certificate serial number hardcoded to 1.  Note that this may cause issues if a single website has multiple certificates.
2. SAN DNS name hardcoded to the specific domain name being looked up.  Note that this means a certificate is only valid for one domain name.  SNI should be used if a single web server serves more than one domain name.
3. Validity period (NotBefore and NotAfter) specified by the name value.
4. ECDSA public key specified by the name value.  Note that we do not support RSA keys, because ECDSA has smaller keys and signatures.
5. ECDSA signature specified by the name value.
6. CA bit disabled; the certificate is only usable as an end entity certificate.
7. KeyUsage hardcoded to "DigitalSignature".  Note that we disallow "KeyEncipherment" because that is only used for RSA key exchange (no forward secrecy), and everyone should be using DHE/ECDHE key exchange (which has forward secrecy) now. 
8. Subject serial number of "Namecoin TLS Certificate".  This is so that if an end user comes across one of our certificates in his or her trust store later, it will be obvious where it came from.
9. Everything else at the default best practices for TLS server certificates.

We call the data that must be stored in the Namecoin value a "dehydrated certificate", and a full certificate generated from that data is called a "rehydrated cert".  An example dehydrated certificate, with base64 encoding for the public key and signature, and integer encoding for the validity period, is as follows:

    ["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvSJuG7K8RYX7toL8iqHnh2d+lMnbqr57pioQzicDpmGooMiKaufVoiJg1fJFUiI2EEbvYO/GjrAFsbCFmzC3Vg==",1420070400,1577836799,10,"MEQCIH/EE6yYEuAlGUIv88VSuBDz4tVWdgWHwJThnU0kiSAsAiBHkXaeFgy5btNpgOvfiIcrovuvkatn3VhrE6Ix3N7TZQ=="]

This is 252 bytes; easily enough to fit into a Namecoin value.

We have provided a command-line tool for generating these certificates, resulting in a dehydrated certificate that can be pasted into a Namecoin value, and a rehydrated certificate that can easily be imported into a web server.  For example:

    $ ./generate_nmc_cert --host www.example.bit --ecdsa-curve P256 --start-date "Jan 1 00:00:00 2015" --end-date "Dec 31 23:59:59 2019"
    2015/11/26 02:42:22 written cert.pem
    2015/11/26 02:42:22 written key.pem
    2015/11/26 02:42:22 Your NMC cert is: ["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvSJuG7K8RYX7toL8iqHnh2d+lMnbqr57pioQzicDpmGooMiKaufVoiJg1fJFUiI2EEbvYO/GjrAFsbCFmzC3Vg==",1420070400,1577836799,10,"MEQCIH/EE6yYEuAlGUIv88VSuBDz4tVWdgWHwJThnU0kiSAsAiBHkXaeFgy5btNpgOvfiIcrovuvkatn3VhrE6Ix3N7TZQ=="]
    2015/11/26 02:42:22 SUCCESS: The cert decompressed to an identical form.

Making dehydrated certificates work properly in Golang was tricky, because the x.509 library functions which are needed to splice a signature into a certificate are private.  We ended up forking the x.509 package, and adding a single file to it which exposed the necessary functionality as a public function.
    
Credit for the idea of dehydrated certificates is due to Ryan Castellucci.

## HPKP

We ~~abuse~~ *take advantage of* an interesting quirk in browser implementations of HPKP (HTTPS Public Key Pinning).  Browsers only enforce key pins against certificates for built-in certificate authorities; user-specified certificate authorities are exempt from HPKP.  This behavior is presumably to make it easier for users to intentionally intercept their own traffic (or for corporations to intercept traffic in their network, which is a less ethical version of a technologically identical concept).  As such, we believe that this behavior will not go away anytime soon, and is safe to rely on.  We place a key pin at the "bit" domain, with subdomains enabled, for a "nothing up my sleeve" public key hash.  As a result, no public CA can sign certificates for any domain ending in ".bit", but user-specified CA's can.  Windows CryptoAPI treats user-specified end-entity certificates as user-specified CA's for this purpose.  As such, rehydrated certificates that we generate will be considered valid, but nothing else will.  (Unless you installed another user-specified CA on your machine that is valid for .bit.  But if you did that, then either you want to intercept .bit, in which case it's fine, or you did it against your will, in which case you are already screwed.)

## Instructions

### Installation

1. Install namecoind or Namecoin-Qt from https://namecoin.org .
2. Configure Namecoin to accept RPC connections (same procedure as Bitcoin).
3. Let Namecoin fully download the blockchain (takes circa 5 hours).
4. Install dnssec-trigger from https://www.nlnetlabs.nl/projects/dnssec-trigger/ or your package manager.
5. Install Go from https://golang.org/dl/
6. go get github.com/hlandau/ncdns
7. Replace the ncdns repo contents with this modified version.
8. If on Linux run "x509_build/install.sh" , on Windows create a subdirectory of ncdns called "x509", copy C:\Go\src\crypto\x509\*.go to x509, and copy the .go file from x509_build to x509.
9. go install github.com/hlandau/ncdns
10. Modify the Unbound config file that dnssec-trigger installed to include the lines at https://github.com/hlandau/ncdns.t#using-ncdns-with-a-recursive-resolver , including the domain-insecure line.
11. Create "$GOPATH/etc/ncdns.conf", with content similar to https://forum.namecoin.org/viewtopic.php?p=16072#p16072 .  Make sure the bind port is the same as what you entered in Unbound's config file, and that the Namecoin RPC data is what your namecoind is set to.
12. In Chromium/Chrome, go to chrome://net-internals/#hsts
13. Under "Add domain", enter the following: domain "bit", STS unchecked, PKP checked, fingerprint "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".  The fingerprint is a "nothing up my sleeve" value; no one has a private key whose public key hashes to that.
14. Click "Add".
15. Reboot your computer to make sure that dnssec-trigger reloads your configuration.

### Creating and deploying an HTTPS certificate

1. go install github.com/hlandau/ncdns/generate_nmc_cert
2. ./generate_nmc_cert --host www.example.bit --ecdsa-curve P256 --start-date "Jan 1 00:00:00 2015" --end-date "Dec 31 23:59:59 2019"
3. Take the cert and key files generated; configure your HTTPS server to use them for your .bit domain.
4. Take the NMC cert listed in the standard output; place it in your Namecoin name using the following template:

    {"map":{"www":{"ip":"YOUR IP HERE", "map":{"_tcp":{"map":{"_443":{"tls":[["c0","c0","c0", YOUR CERT HERE]]}}}}}}}

For example:

    {"map":{"www":{"ip":"123.45.67.89", "map":{"_tcp":{"map":{"_443":{"tls":[["c0","c0","c0", ["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvSJuG7K8RYX7toL8iqHnh2d+lMnbqr57pioQzicDpmGooMiKaufVoiJg1fJFUiI2EEbvYO/GjrAFsbCFmzC3Vg==",1420070400,1577836799,10,"MEQCIH/EE6yYEuAlGUIv88VSuBDz4tVWdgWHwJThnU0kiSAsAiBHkXaeFgy5btNpgOvfiIcrovuvkatn3VhrE6Ix3N7TZQ=="]]]}}}}}}}

A live example is at https://www.veclabs.bit (block explorer link at https://namecha.in/name/d/veclabs for people who don't have Namecoin installed).

### Running It

1. Run ncdns as an administrator.  (Yes, it sucks that you need admin privileges; we think it is possible to fix this with some additional effort that we will do after the hackathon is over.)
2. Visit a .bit website that uses HTTPS.  For example, https://www.veclabs.bit .  (That site has broken images because of server config issues, but HTTPS should work without certificate errors.)
3. The page will load successfully.  Yay!

Note: while the "correct" TLS cert will be trusted on any application that uses Windows CryptoAPI, and "incorrect" TLS certs that are not signed by a default trusted CA will be rejected on any such application, only Chrome will protect you from TLS certs that are not "correct" in the Namecoin blockchain but which have been signed by a default trusted CA (i.e. a CA that Windows comes with and is used for non-.bit domains).  This is because Chrome is the only CryptoAPI browser that supports HPKP.  Therefore, for maximum protection from malicious certs, you should not visit .bit websites in browsers other than Chrome.

## Future Direction

There are a number of things we would like to improve in this scheme.

### Support Other Trust Stores

Among other things, we would like to support NSS (used by Firefox, and the OSX/Linux versions of Chromium/Chrome), and OpenSSL (used by many applications on Linux).

### Direct Registry Access to CryptoAPI Trust Store

The certificates generated by ncdns-tls are stored by Windows certutil in the registry key HKLM\SOFTWARE\Wow6432Node\Microsoft\EnterpriseCertificates\Root\Certificates.  We believe that it is possible to directly add certificates to this registry key without going through certutil.  This means that we can apply the Windows registry permission system, which would eliminate the need for ncdns-tls to be run as an administrator.  It would also allow us to delete certificates that are outdated, since the registry keeps track of a "last modified" timestamp.

### DNSSEC Dehydrated Certificate Retrieval

Right now, our ncdns callback only checks for TLSA records that exist in Namecoin.  It would make more sense to perform an actual TLSA DNS lookup, so that TLSA records that have been delegated to a nameserver using DNSSEC would work as well.  (This also is needed in order to allow non-.bit domains to be supported.)  This would require checking the AD flag in DNS responses, to make sure that a nameserver that doesn't implement DNSSEC can't provide TLSA records (since that would be insecure).  Note that DNSSEC is slightly less secure than Namecoin since DNSSEC signatures expire after about a month, while a Namecoin blockchain is considered outdated after 2 hours, so DNSSEC gives the attacker more time to perform a replay attack.

### Network Dehydrated Certificate Retrieval

In some cases, no dehydrated certificate can be obtained from Namecoin or DNSSEC.  This may be because a TLSA record only contains a hash or a public key instead of the full certificate.  In such cases, ncdns-tls could perform a TLS handshake with the destination to retrieve a certificate, and then consider it valid if the hash or public key matches the TLSA record.  This would require carefulness, since performing a TLS handshake would usually trigger a DNS lookup, which results in an infinite recursion loop of DNS lookups and TLS handshakes.  A solution might be to do a TLS handshake with "example.bit.bit-no-hook", since ncdns supports domain suffixes, and then explicitly choose "example.bit" as the SNI header.

### Proxy-Compatible Dehydrated Certificate Retrieval

Relying on DNS hooks for retrieving certificates means that browsers which use DNS over a proxy (in particular TorBrowser) won't trigger the hook.  Chromium/Chrome and Firefox/TorBrowser support an API to run Javascript hooks prior to issuing an HTTP request.  Using these hooks would allow users who have a proxy configured to still trigger the rehydrated certificate injection.  It is also needed in order to enable non-.bit websites (which don't get passed to ncdns) to use dehydrated certificates.

### Notary Dehydrated Certificate Retrieval

Non-.bit websites which don't have a TLSA record could have TLSA records generated from notaries such as what Perspectives provides.

### Firefox cert injection / Windows

NSS on Windows does not provide any easy way to inject certificates to its trust store (unless the user builds NSS-Tools from source).  However, Firefox does expose an API to extensions which want to do this.  Therefore, providing this option to Firefox users would make things easier.

### More Thorough Dehydration

It may be possible to further dehydrate the certificates, e.g. by using compressed public keys, reducing the precision of the validity period, or using more compact encoding than base64.

### HSTS Simulation

A website which has a known TLSA record should be able to be automatically redirected from HTTP to HTTPS using a browser extension.  This would protect against sslstrip attacks (similar to HSTS but without trusting the first use).  However, it would also break a tiny subset of websites which list a TLSA record but only serve content on HTTP.

### Test for Validation Bugs

We should carefully test x.509 implementations for bugs that might interact badly with our code.  For example, if a bug in a major browser caused certificates without the CA bit to be usable as CA's, that would be very bad.  We think it is unlikely that such major bugs exist, given that major browser vendors have had many years to review their code.  But one can't be too careful.