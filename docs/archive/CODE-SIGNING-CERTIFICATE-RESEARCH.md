# EV CODE SIGNING CERTIFICATE RESEARCH
**Research Date:** November 3, 2025
**Purpose:** Mainnet launch preparation - eliminate Windows SmartScreen warnings
**Project:** Dilithion Post-Quantum Cryptocurrency

---

## EXECUTIVE SUMMARY

**Recommendation:** Sectigo EV Code Signing Certificate ($279-380/year)

**Rationale:**
- Industry-standard trust and compatibility
- Immediate SmartScreen reputation (EV benefit)
- Professional-grade security (hardware token included)
- Cost-effective for 3-year cryptocurrency project timeline
- Fast issuance (5-7 business days typical)

**Total 3-Year Cost Projection:**
- Sectigo: $840-1,140 (best value)
- DigiCert: $1,497-2,097 (premium option)
- SSL.com: $900-1,200 (competitive alternative)

---

## DETAILED PROVIDER COMPARISON

### Provider 1: Sectigo (Formerly Comodo)
**Website:** sectigo.com / comodosslstore.com

**Pricing (2025):**
- Direct: $279-290/year
- Via TheSSLStore: $380/year
- Via SSL2Buy: $423/year
- Via SectigoStore: $290/year

**Best Price Found:** $279/year direct or via authorized resellers

**Strengths:**
- Excellent price-to-value ratio
- Fast issuance (5-7 business days)
- 30-day money-back guarantee
- Strong SmartScreen reputation integration
- Hardware token included (USB/YubiKey compatible)
- 24/7 customer support
- Widely trusted by all major platforms

**Requirements:**
- Business registration verification
- DUNS number or equivalent
- Operational phone verification
- Legal existence documentation
- Physical address verification

**Validation Time:** 5-7 business days

**Compatibility:**
- Windows (all versions)
- macOS code signing
- Linux package signing
- Java code signing
- Microsoft Office macros

**Assessment:** Best overall value for cryptocurrency project

---

### Provider 2: DigiCert
**Website:** digicert.com

**Pricing (2025):**
- Standard EV: $499-699/year
- Premium support: +$100-200/year

**Best Price Found:** $499/year via SignMyCode reseller

**Strengths:**
- Premium brand recognition
- Fastest SmartScreen reputation building
- Excellent technical support
- Industry leader, trusted by Fortune 500
- Advanced threat intelligence integration
- Hardware token included (YubiKey)
- Same-day issuance possible (priority verification)

**Requirements:**
- Business registration verification
- DUNS number required
- Operational verification call
- Third-party documentation (lawyer's letter, etc.)
- Extensive background checks

**Validation Time:** 3-5 business days (can expedite to 1-2 days)

**Compatibility:**
- Windows (all versions)
- macOS code signing
- Linux package signing
- Java code signing
- Adobe AIR applications
- Microsoft Office macros

**Assessment:** Premium option, best for enterprises requiring maximum brand trust

---

### Provider 3: SSL.com
**Website:** ssl.com

**Pricing (2025):**
- EV Code Signing: $299-399/year
- eSigner Cloud HSM: Included with EV

**Best Price Found:** $299/year

**Strengths:**
- Competitive pricing
- Cloud HSM option (no physical token shipping)
- Good SmartScreen integration
- FIPS 140-2 Level 2 compliant
- Malware scanning included
- Docker image signing support
- Timestamp service included (10 years validity)

**Unique Features:**
- eSigner cloud-based signing (no USB token needed)
- Remote signing API for CI/CD integration
- Built-in malware scanning before signing

**Requirements:**
- Business verification (standard process)
- Identity validation
- Phone verification
- Government-issued ID

**Validation Time:** 3-7 business days

**Compatibility:**
- Windows (all versions)
- macOS
- Linux
- Docker containers
- Java applications

**Assessment:** Modern option with cloud-based signing, good for distributed teams

---

### Provider 4: GlobalSign
**Website:** globalsign.com

**Pricing (2025):**
- EV Code Signing: $449-599/year

**Best Price Found:** $449/year via resellers

**Strengths:**
- Established reputation (since 1996)
- European-based CA (good for international projects)
- Strong compliance record
- Hardware token included
- Good customer support
- Multi-year discounts available

**Requirements:**
- Business registration
- Legal documentation
- Operational verification
- Physical address confirmation

**Validation Time:** 5-10 business days

**Compatibility:**
- Windows
- macOS
- Java
- Adobe AIR

**Assessment:** Solid choice, slightly slower issuance than competitors

---

### Provider 5: GoGetSSL (Reseller)
**Website:** gogetssl.com

**Pricing (2025):**
- Sectigo EV via GoGetSSL: $284.25/year

**Note:** This is a reseller offering Sectigo certificates at discounted rates

**Strengths:**
- Lowest price found for Sectigo EV
- Same certificate authority (Sectigo)
- Same security and trust level
- Lower overhead (reseller model)

**Considerations:**
- Support goes through reseller (not direct CA)
- Validation still handled by Sectigo
- Same hardware token and issuance process

**Assessment:** Best price for Sectigo certificates, acceptable for budget-conscious projects

---

## KEY REQUIREMENTS FOR ALL EV CERTIFICATES

### Business Verification Documents:
1. **Articles of Incorporation** or business registration
2. **DUNS Number** (Dun & Bradstreet)
   - Free to obtain at dnb.com
   - Takes 30 days to establish
   - Required by most CAs
3. **Operational Verification:**
   - Business phone line (listed in public directory)
   - Physical business address
   - Verified by CA via phone call
4. **Legal Documentation:**
   - Attorney's letter (some CAs)
   - Accountant opinion letter
   - Government-issued business license
5. **Identity Verification:**
   - Government-issued photo ID
   - Proof of authority to sign on behalf of business

### Individual Developer Option:
Some CAs offer "individual" EV certificates with:
- Personal identity verification (passport, driver's license)
- Lower documentation requirements
- Same technical capabilities
- Slightly lower trust reputation for businesses

**Note:** For cryptocurrency project, business certificate is recommended

---

## HARDWARE TOKEN REQUIREMENTS

All EV certificates require private key storage on hardware token (HSM):

**Typical Hardware:**
- USB token (FIPS 140-2 Level 2 certified)
- YubiKey (supported by most CAs)
- SafeNet eToken
- Thales Luna HSM (enterprise)

**Security Features:**
- Private key never leaves token
- PIN protection
- Physical possession required for signing
- Tamper-resistant

**Shipping:**
- CAs ship token after validation complete
- Express shipping available ($20-50 extra)
- International shipping supported

**Backup:**
- Some CAs offer backup token ($50-100)
- Recommended for business continuity

---

## SIGNING PROCESS OVERVIEW

Once certificate is obtained:

### Windows Signing Command:
```powershell
# Install Windows SDK (includes signtool.exe)
# https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

# Sign executable
signtool sign /fd SHA256 /tr http://timestamp.sectigo.com /td SHA256 /f certificate.pfx /p password dilithion-node.exe

# Verify signature
signtool verify /pa dilithion-node.exe

# Check signature details
Get-AuthenticodeSignature .\dilithion-node.exe | Format-List
```

### Timestamp Server Importance:
- Certificates expire (1-3 years)
- Timestamp proves signing occurred when cert was valid
- Signed files remain valid after cert expiration
- Critical for long-term software distribution

**Recommended Timestamp Servers:**
- Sectigo: http://timestamp.sectigo.com
- DigiCert: http://timestamp.digicert.com
- GlobalSign: http://timestamp.globalsign.com

---

## COST-BENEFIT ANALYSIS

### 3-Year Mainnet Timeline:

| Provider | Year 1 | Year 2 | Year 3 | Total 3-Year | Avg/Year |
|----------|--------|--------|--------|--------------|----------|
| Sectigo | $280 | $280 | $280 | $840 | $280 |
| DigiCert | $499 | $499 | $499 | $1,497 | $499 |
| SSL.com | $300 | $300 | $300 | $900 | $300 |
| GlobalSign | $450 | $450 | $450 | $1,350 | $450 |

**Multi-Year Discounts:**
- Sectigo: 10% off for 2-year, 15% off for 3-year ($238/year for 3-year)
- DigiCert: 5% off for 2-year, 10% off for 3-year ($449/year for 3-year)
- SSL.com: 15% off for 3-year ($255/year for 3-year)

**Best 3-Year Deal:** Sectigo 3-year = $714 total ($238/year)

---

## CRYPTOCURRENCY-SPECIFIC CONSIDERATIONS

### Additional Factors for Blockchain Software:

1. **Transparent Chain of Trust:**
   - All major CAs provide public certificate transparency logs
   - Sectigo, DigiCert, and GlobalSign all participate in CT logs
   - Users can independently verify certificate validity

2. **Decentralization Philosophy:**
   - Code signing uses centralized CAs (unavoidable)
   - However, source code remains open and verifiable
   - Users can compile from source if they distrust binaries
   - Certificate only validates publisher identity, not code integrity

3. **Reproducible Builds:**
   - Consider implementing reproducible build process
   - Users can verify binary matches source code
   - Certificate proves "who built it"
   - Reproducible builds prove "what was built"

4. **Multi-Signature Option:**
   - Some projects use multiple signatures
   - Example: One signature from company, one from lead developer
   - Adds redundancy and trust
   - More complex to manage

---

## PROCUREMENT TIMELINE

### For Mainnet Launch (January 1, 2026):

**Critical Path:**

**Week 1-2 (Mid-November):**
- Obtain DUNS number (if don't have one)
- Gather business verification documents
- Select certificate provider
- Initiate purchase and validation

**Week 3-4 (Late November):**
- Complete CA verification process
- Receive hardware token
- Install certificate and test signing
- Sign all release binaries
- Verify signatures

**Week 5-6 (Early December):**
- Upload signed binaries to distribution
- Test downloads on multiple Windows versions
- Verify no SmartScreen warnings
- Update documentation

**Buffer:** 2-4 weeks before mainnet launch

**Recommended Start Date:** November 15, 2025 (latest)

---

## FINAL RECOMMENDATION

### For Dilithion Project:

**Primary Choice: Sectigo EV Code Signing Certificate**

**Purchase Option:**
- **Direct from Sectigo:** $279-290/year
- **Via GoGetSSL:** $284.25/year (reseller, slight savings)
- **3-Year Package:** $714 total ($238/year) - Best value

**Rationale:**
1. **Professional Standard:** Industry-recognized CA, widely trusted
2. **Cost-Effective:** 40-50% less than DigiCert, same technical benefits
3. **Instant Reputation:** EV certificate provides immediate SmartScreen trust
4. **Fast Issuance:** 5-7 business days typical
5. **Comprehensive Support:** 24/7 availability, good documentation
6. **Hardware Token Included:** Secure key storage, FIPS 140-2 compliant
7. **Long History:** Formerly Comodo, operating since 1998

**Alternative: DigiCert (if budget allows)**
- Choose if "premium brand recognition" is worth extra $220/year
- Marginal benefit for cryptocurrency project
- Same technical security as Sectigo

**Budget Alternative: SSL.com**
- Good middle ground at $299/year
- Cloud HSM option useful for distributed teams
- Newer CA but good compliance record

---

## IMPLEMENTATION CHECKLIST

**Before Purchase:**
- [ ] Obtain DUNS number (if needed)
- [ ] Gather business registration documents
- [ ] Set up business phone line verification
- [ ] Prepare legal documentation
- [ ] Budget approval for certificate cost

**During Purchase:**
- [ ] Complete CA application form
- [ ] Submit verification documents
- [ ] Complete verification phone call
- [ ] Wait for validation (5-7 days)
- [ ] Receive and configure hardware token

**After Receipt:**
- [ ] Install Windows SDK (signtool.exe)
- [ ] Test signing process with test executable
- [ ] Document signing procedure
- [ ] Sign all release binaries
- [ ] Verify signatures on multiple systems
- [ ] Archive signed binaries securely

**Ongoing:**
- [ ] Sign all future releases with same certificate
- [ ] Monitor certificate expiration (set reminder 60 days before)
- [ ] Renew certificate before expiration
- [ ] Maintain hardware token security

---

## SECURITY BEST PRACTICES

1. **Hardware Token Protection:**
   - Store in secure location when not in use
   - Use strong PIN (not default)
   - Order backup token
   - Never share or photograph token

2. **Signing Environment:**
   - Sign on isolated, air-gapped machine if possible
   - Scan binaries for malware before signing
   - Use clean build environment
   - Document build and signing process

3. **Certificate Management:**
   - Store certificate credentials securely (password manager)
   - Limit access to signing hardware
   - Maintain audit log of all signatures
   - Revoke certificate immediately if compromised

4. **Transparency:**
   - Publish certificate fingerprint on website
   - Provide verification instructions to users
   - Maintain public log of signed releases
   - Respond promptly to signature issues

---

## ADDITIONAL RESOURCES

**Certificate Authority Selection:**
- CA/Browser Forum: https://cabforum.org
- Certificate Transparency Project: https://certificate.transparency.dev

**Windows Code Signing:**
- Microsoft Docs: https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools
- Signtool.exe Reference: https://docs.microsoft.com/en-us/dotnet/framework/tools/signtool-exe

**DUNS Number:**
- D&B Registration: https://www.dnb.com/duns-number.html

**Security Standards:**
- FIPS 140-2: https://csrc.nist.gov/publications/detail/fips/140/2/final
- CA/B Forum Baseline Requirements: https://cabforum.org/baseline-requirements-documents/

---

## APPENDIX: ALTERNATIVE APPROACHES (Not Recommended)

### Self-Signed Certificates
**Cost:** $0
**Effectiveness:** 0% (triggers even more warnings)
**Assessment:** Never use for production software

### Open Source Signature Solutions
**Examples:** SignPath, Sigstore
**Status:** Experimental, not widely recognized by Windows
**Assessment:** Interesting for future, not ready for production cryptocurrency

### Delay Until Reputation Builds
**Timeline:** 2-12 months
**Risk:** Lost users, damaged reputation, appears unprofessional
**Assessment:** Unacceptable for mainnet launch with real value

---

**Document Version:** 1.0
**Next Review:** Before mainnet launch (December 2025)
**Owner:** Dilithion Project Lead
**Status:** Decision pending - recommend Sectigo EV 3-year package
