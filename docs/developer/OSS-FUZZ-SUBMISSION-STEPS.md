# OSS-Fuzz Submission Steps

**Phase 9.3: Step-by-Step Guide**

This guide provides detailed steps to submit Dilithion to Google OSS-Fuzz.

---

## Prerequisites

✅ **Completed:**
- Fuzz targets created (23 harnesses, 80+ targets)
- Build system configured
- ClusterFuzzLite configuration created

⏳ **Required:**
- GitHub account
- Fork of google/oss-fuzz repository

---

## Step 1: Fork OSS-Fuzz Repository

1. **Go to OSS-Fuzz Repository:**
   - Visit: https://github.com/google/oss-fuzz

2. **Fork the Repository:**
   - Click "Fork" button (top right)
   - Choose your GitHub account
   - Wait for fork to complete

3. **Clone Your Fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/oss-fuzz.git
   cd oss-fuzz
   ```

---

## Step 2: Create Project Directory

1. **Navigate to Projects Directory:**
   ```bash
   cd projects
   ```

2. **Create Dilithion Directory:**
   ```bash
   mkdir dilithion
   cd dilithion
   ```

---

## Step 3: Add Project Files

Copy the files from `projects/dilithion/` in this repository:

1. **project.yaml:**
   ```bash
   # Copy from: projects/dilithion/project.yaml
   # To: oss-fuzz/projects/dilithion/project.yaml
   ```

2. **Dockerfile:**
   ```bash
   # Copy from: projects/dilithion/Dockerfile
   # To: oss-fuzz/projects/dilithion/Dockerfile
   ```

3. **build.sh:**
   ```bash
   # Copy from: projects/dilithion/build.sh
   # To: oss-fuzz/projects/dilithion/build.sh
   chmod +x build.sh
   ```

**Files Location in This Repository:**
- `projects/dilithion/project.yaml`
- `projects/dilithion/Dockerfile`
- `projects/dilithion/build.sh`

---

## Step 4: Update Configuration

1. **Edit project.yaml:**
   - Update `maintainers` with your email
   - Update `primary_contact` with your email
   - Update `auto_ccs` with your email

2. **Verify Dockerfile:**
   - Check dependency URLs are correct
   - Verify build commands

3. **Verify build.sh:**
   - Check fuzz target names match your Makefile
   - Verify environment variables

---

## Step 5: Test Build Locally (Optional)

1. **Build Docker Image:**
   ```bash
   cd oss-fuzz
   python3 infra/helper.py build_image dilithion
   ```

2. **Test Build:**
   ```bash
   python3 infra/helper.py build_fuzzers dilithion
   ```

3. **Run Fuzzer:**
   ```bash
   python3 infra/helper.py run_fuzzer dilithion fuzz_sha3
   ```

**If build fails:**
- Check error messages
- Fix issues in Dockerfile or build.sh
- Re-test

---

## Step 6: Commit and Push

1. **Add Files:**
   ```bash
   cd oss-fuzz
   git add projects/dilithion/
   ```

2. **Commit:**
   ```bash
   git commit -m "Add Dilithion project to OSS-Fuzz

   - Add project.yaml configuration
   - Add Dockerfile for build environment
   - Add build.sh for fuzz target compilation
   - Supports 7 fuzz targets (sha3, transaction, block, serialize, mempool, rpc, p2p_validation)"
   ```

3. **Push to Your Fork:**
   ```bash
   git push origin main
   ```

---

## Step 7: Create Pull Request

1. **Go to Your Fork:**
   - Visit: https://github.com/YOUR_USERNAME/oss-fuzz

2. **Create Pull Request:**
   - Click "Compare & pull request"
   - Title: "Add Dilithion project to OSS-Fuzz"
   - Description:
     ```
     This PR adds Dilithion, a post-quantum cryptocurrency, to OSS-Fuzz.

     Dilithion uses:
     - CRYSTALS-Dilithium3 (NIST FIPS 204) for signatures
     - SHA-3/Keccak-256 for hashing
     - RandomX for proof-of-work

     Fuzz targets:
     - fuzz_sha3: SHA-3 hashing
     - fuzz_transaction: Transaction deserialization
     - fuzz_block: Block header validation
     - fuzz_serialize: Serialization/deserialization
     - fuzz_mempool: Mempool operations
     - fuzz_rpc: RPC parsing
     - fuzz_p2p_validation: P2P message validation

     Repository: https://github.com/WillBarton888/dilithion
     ```

3. **Submit PR:**
   - Click "Create pull request"
   - Wait for OSS-Fuzz team review

---

## Step 8: Monitor PR

1. **Check PR Status:**
   - OSS-Fuzz team will review
   - They may request changes
   - Address feedback promptly

2. **CI Checks:**
   - OSS-Fuzz CI will test build
   - Fix any build failures
   - Update PR as needed

3. **Approval:**
   - Once approved, PR will be merged
   - Fuzzing will start automatically

---

## Step 9: Monitor Fuzzing

1. **OSS-Fuzz Dashboard:**
   - Visit: https://oss-fuzz.com/fuzzer-stats/by-project/dilithion
   - View fuzzing statistics
   - Check coverage reports

2. **Bug Reports:**
   - Visit: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=project:dilithion
   - Review reported bugs
   - Fix and verify fixes

3. **Email Notifications:**
   - Configure in OSS-Fuzz settings
   - Receive alerts for new bugs

---

## Troubleshooting

### Build Fails in PR

**Problem:** CI build fails

**Solutions:**
- Check CI logs
- Test build locally
- Fix Dockerfile or build.sh
- Update PR

### Fuzzer Crashes

**Problem:** Fuzzer crashes immediately

**Solutions:**
- Check fuzz target code
- Verify input handling
- Test locally first
- Fix crashes

### No Fuzzing Activity

**Problem:** Fuzzing doesn't start

**Solutions:**
- Wait 24-48 hours after merge
- Check OSS-Fuzz dashboard
- Contact OSS-Fuzz team if needed

---

## Files Reference

**In This Repository:**
- `projects/dilithion/project.yaml` - OSS-Fuzz project config
- `projects/dilithion/Dockerfile` - Build environment
- `projects/dilithion/build.sh` - Build script

**In OSS-Fuzz Repository (after submission):**
- `projects/dilithion/project.yaml`
- `projects/dilithion/Dockerfile`
- `projects/dilithion/build.sh`

---

## Status

**Current Status:** ✅ **READY FOR SUBMISSION**

- ✅ Project files created
- ✅ Configuration complete
- ✅ Build scripts ready
- ⏳ PR to OSS-Fuzz pending

**Next Steps:**
1. Fork google/oss-fuzz
2. Copy project files
3. Create PR
4. Monitor submission

---

**Last Updated:** December 2025

