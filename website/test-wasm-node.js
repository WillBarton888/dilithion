// Node.js test for Dilithium WASM module
const path = require('path');

// Constants
const DILITHIUM3_PUBLICKEY_BYTES = 1952;
const DILITHIUM3_SECRETKEY_BYTES = 4032;
const DILITHIUM3_SIGNATURE_BYTES = 3309;

async function runTests() {
    console.log('=== Dilithium WASM Node.js Test ===\n');

    // Load the WASM module
    console.log('1. Loading WASM module...');
    const DilithiumModule = require('./js/dilithium.js');
    const wasmModule = await DilithiumModule();
    console.log('   WASM loaded successfully');

    // Initialize
    console.log('\n2. Initializing Dilithium...');
    const initResult = wasmModule._dilithium_init();
    console.log('   Init result:', initResult === 0 ? 'SUCCESS' : 'FAILED');
    if (initResult !== 0) {
        console.error('   Failed to initialize Dilithium');
        process.exit(1);
    }

    // Check key sizes
    console.log('\n3. Checking key sizes...');
    const pkBytes = wasmModule._dilithium_get_publickey_bytes();
    const skBytes = wasmModule._dilithium_get_secretkey_bytes();
    const sigBytes = wasmModule._dilithium_get_signature_bytes();
    console.log('   Public key bytes:', pkBytes, pkBytes === DILITHIUM3_PUBLICKEY_BYTES ? '(OK)' : '(WRONG!)');
    console.log('   Secret key bytes:', skBytes, skBytes === DILITHIUM3_SECRETKEY_BYTES ? '(OK)' : '(WRONG!)');
    console.log('   Signature bytes:', sigBytes, sigBytes === DILITHIUM3_SIGNATURE_BYTES ? '(OK)' : '(WRONG!)');

    // Generate keypair
    console.log('\n4. Generating keypair...');
    const pkPtr = wasmModule._dilithium_malloc(DILITHIUM3_PUBLICKEY_BYTES);
    const skPtr = wasmModule._dilithium_malloc(DILITHIUM3_SECRETKEY_BYTES);
    console.log('   Allocated memory: pk@' + pkPtr + ', sk@' + skPtr);

    if (pkPtr === 0 || skPtr === 0) {
        console.error('   Memory allocation failed!');
        process.exit(1);
    }

    const startKeygen = Date.now();
    const keygenResult = wasmModule._dilithium_keypair(pkPtr, skPtr);
    const keygenTime = Date.now() - startKeygen;
    console.log('   Keygen result:', keygenResult === 0 ? 'SUCCESS' : 'FAILED (' + keygenResult + ')');
    console.log('   Keygen time:', keygenTime + 'ms');

    if (keygenResult !== 0) {
        console.error('   Failed to generate keypair');
        wasmModule._dilithium_free(pkPtr);
        wasmModule._dilithium_free(skPtr);
        process.exit(1);
    }

    // Copy keys from WASM memory
    const publicKey = new Uint8Array(wasmModule.HEAPU8.buffer, pkPtr, DILITHIUM3_PUBLICKEY_BYTES).slice();
    const privateKey = new Uint8Array(wasmModule.HEAPU8.buffer, skPtr, DILITHIUM3_SECRETKEY_BYTES).slice();
    console.log('   Public key: first 16 bytes =', Buffer.from(publicKey.slice(0, 16)).toString('hex'));
    console.log('   Private key: first 16 bytes =', Buffer.from(privateKey.slice(0, 16)).toString('hex'));

    // Sign a message
    console.log('\n5. Signing message...');
    const message = Buffer.from('Hello, Dilithion!');
    const msgPtr = wasmModule._dilithium_malloc(message.length);
    const sigPtr = wasmModule._dilithium_malloc(DILITHIUM3_SIGNATURE_BYTES);
    const sigLenPtr = wasmModule._dilithium_malloc(8);

    wasmModule.HEAPU8.set(message, msgPtr);
    wasmModule.HEAPU8.set(privateKey, skPtr);  // Re-use skPtr

    const startSign = Date.now();
    const signResult = wasmModule._dilithium_sign(sigPtr, sigLenPtr, msgPtr, message.length, skPtr);
    const signTime = Date.now() - startSign;
    console.log('   Sign result:', signResult === 0 ? 'SUCCESS' : 'FAILED (' + signResult + ')');
    console.log('   Sign time:', signTime + 'ms');

    if (signResult !== 0) {
        console.error('   Failed to sign');
        process.exit(1);
    }

    // Get signature length
    const sigLen = wasmModule.HEAPU32[sigLenPtr >> 2];
    console.log('   Signature length:', sigLen, 'bytes');
    const signature = new Uint8Array(wasmModule.HEAPU8.buffer, sigPtr, sigLen).slice();

    // Verify signature
    console.log('\n6. Verifying signature...');
    wasmModule.HEAPU8.set(publicKey, pkPtr);  // Re-use pkPtr

    const startVerify = Date.now();
    const verifyResult = wasmModule._dilithium_verify(msgPtr, message.length, sigPtr, sigLen, pkPtr);
    const verifyTime = Date.now() - startVerify;
    console.log('   Verify result:', verifyResult === 0 ? 'VALID' : 'INVALID');
    console.log('   Verify time:', verifyTime + 'ms');

    // Verify with wrong message
    console.log('\n7. Verifying with wrong message...');
    const wrongMsg = Buffer.from('Wrong message');
    const wrongMsgPtr = wasmModule._dilithium_malloc(wrongMsg.length);
    wasmModule.HEAPU8.set(wrongMsg, wrongMsgPtr);

    const wrongVerifyResult = wasmModule._dilithium_verify(wrongMsgPtr, wrongMsg.length, sigPtr, sigLen, pkPtr);
    console.log('   Verify result (should be INVALID):', wrongVerifyResult === 0 ? 'VALID (ERROR!)' : 'INVALID (CORRECT)');

    // Cleanup
    wasmModule._dilithium_free(pkPtr);
    wasmModule._dilithium_free(skPtr);
    wasmModule._dilithium_free(msgPtr);
    wasmModule._dilithium_free(sigPtr);
    wasmModule._dilithium_free(sigLenPtr);
    wasmModule._dilithium_free(wrongMsgPtr);
    wasmModule._dilithium_cleanup();

    console.log('\n=== All tests passed! ===');
}

runTests().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
});
