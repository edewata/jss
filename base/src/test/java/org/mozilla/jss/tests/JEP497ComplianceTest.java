//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package org.mozilla.jss.tests;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.PasswordCallback;

/**
 * JEP 497 Compliance Test
 *
 * This test validates compliance with JEP 497: Quantum-Resistant Module-Lattice-Based
 * Digital Signature Algorithm (ML-DSA) as standardized in NIST FIPS 204.
 *
 * JEP 497 specifies support for three ML-DSA parameter sets:
 * - ML-DSA-44: Category 2 security (equivalent to AES-128)
 * - ML-DSA-65: Category 3 security (equivalent to AES-192)
 * - ML-DSA-87: Category 5 security (equivalent to AES-256)
 */
public class JEP497ComplianceTest {

    // ML-DSA parameter sets as specified in JEP 497 and FIPS 204
    private static final List<String> ML_DSA_PARAMETER_SETS = Arrays.asList(
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87"
    );

    // Test vectors - sample data for signing
    private static final byte[] TEST_DATA_SMALL = "Hello, Quantum-Resistant World!".getBytes();
    private static final byte[] TEST_DATA_MEDIUM = new byte[1024];
    private static final byte[] TEST_DATA_LARGE = new byte[8192];

    static {
        // Initialize test vectors with deterministic data
        for (int i = 0; i < TEST_DATA_MEDIUM.length; i++) {
            TEST_DATA_MEDIUM[i] = (byte)(i & 0xFF);
        }
        for (int i = 0; i < TEST_DATA_LARGE.length; i++) {
            TEST_DATA_LARGE[i] = (byte)((i * 17 + 42) & 0xFF);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            usage();
            System.exit(1);
        }

        String dbdir = args[0];
        String passwordFile = args[1];

        InitializationValues vals = new InitializationValues(dbdir);
        vals.removeSunProvider = false;
        vals.installJSSProvider = true;

        CryptoManager.initialize(vals);

        PasswordCallback cb = new FilePasswordCallback(passwordFile);

        // Initialize Mozilla-JSS CryptoManager
        CryptoManager manager = CryptoManager.getInstance();
        manager.setPasswordCallback(cb);

        CryptoToken token = manager.getInternalKeyStorageToken();
        token.login(cb);

        manager.setThreadToken(token);

        System.out.println("=== JEP 497 ML-DSA Compliance Test ===");
        System.out.println("Testing Mozilla-JSS provider compliance with NIST FIPS 204 ML-DSA");

        // Test provider availability and registration
        testProviderAvailability();

        // Test all ML-DSA parameter sets
        for (String parameterSet : ML_DSA_PARAMETER_SETS) {
            testMLDSAParameterSet(parameterSet);
        }

        // Test cross-parameter compatibility (should fail appropriately)
        testCrossParameterCompatibility();

        // Test algorithm naming compliance
        testAlgorithmNaming();

        // Test edge cases and error conditions
        testErrorConditions();

        System.out.println("=== JEP 497 Compliance Test PASSED ===");
        System.out.println("Mozilla-JSS provider is compliant with JEP 497 ML-DSA specification");
    }

    public static void usage() {
        System.out.println("Usage: java org.mozilla.jss.tests.JEP497ComplianceTest <dbdir> <passwordFile>");
        System.out.println("  dbdir: NSS database directory");
        System.out.println("  passwordFile: File containing NSS database password");
    }

    /**
     * Test that the Mozilla-JSS provider properly supports ML-DSA algorithms
     */
    private static void testProviderAvailability() throws Exception {
        System.out.println("\n--- Testing Provider Availability ---");

        Provider[] providers = Security.getProviders();
        Provider jsProvider = null;

        for (Provider provider : providers) {
            if ("Mozilla-JSS".equals(provider.getName())) {
                jsProvider = provider;
                break;
            }
        }

        if (jsProvider == null) {
            throw new Exception("Mozilla-JSS provider not found in Security providers");
        }

        System.out.println("Found Mozilla-JSS provider: " + jsProvider.getInfo());

        // Verify ML-DSA algorithms are registered
        for (String paramSet : ML_DSA_PARAMETER_SETS) {
            if (jsProvider.getService("Signature", paramSet) != null &&
                jsProvider.getService("KeyPairGenerator", paramSet) != null) {
                System.out.println("✓ " + paramSet + " algorithms are registered");
            } else {
                throw new Exception(paramSet + " algorithms are not properly registered in Mozilla-JSS provider");
            }
        }

        // Test generic ML-DSA algorithm availability
        if (jsProvider.getService("Signature", "ML-DSA") != null) {
            System.out.println("✓ Generic ML-DSA signature algorithm is available");
        }

        System.out.println("Provider availability test passed");
    }

    /**
     * Comprehensive test for a specific ML-DSA parameter set
     */
    private static void testMLDSAParameterSet(String parameterSet) throws Exception {
        System.out.println("\n--- Testing " + parameterSet + " ---");

        // Test key pair generation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(parameterSet, "Mozilla-JSS");
        if (!"Mozilla-JSS".equals(kpg.getProvider().getName())) {
            throw new Exception("Expected Mozilla-JSS provider for " + parameterSet +
                              " but got " + kpg.getProvider().getName());
        }

        System.out.println("✓ KeyPairGenerator for " + parameterSet + " using Mozilla-JSS");

        // Generate key pair
        KeyPair keyPair = kpg.generateKeyPair();
        if (keyPair == null || keyPair.getPublic() == null || keyPair.getPrivate() == null) {
            throw new Exception("Failed to generate key pair for " + parameterSet);
        }

        System.out.println("✓ Key pair generation successful for " + parameterSet);

        // Test key properties
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("  Public key algorithm: " + publicKey.getAlgorithm());
        System.out.println("  Private key algorithm: " + privateKey.getAlgorithm());
        System.out.println("  Public key format: " + publicKey.getFormat());

        // Test signature creation and verification with different data sizes
        testSignatureOperations(parameterSet, keyPair, TEST_DATA_SMALL, "small data");
        testSignatureOperations(parameterSet, keyPair, TEST_DATA_MEDIUM, "medium data (1KB)");
        testSignatureOperations(parameterSet, keyPair, TEST_DATA_LARGE, "large data (8KB)");

        // Test determinism - signatures should be different each time (due to randomness)
        testSignatureRandomness(parameterSet, keyPair);

        System.out.println("✓ " + parameterSet + " parameter set test completed successfully");
    }

    /**
     * Test signature operations (sign and verify) for given data
     */
    private static void testSignatureOperations(String parameterSet, KeyPair keyPair,
                                              byte[] testData, String description) throws Exception {

        // Test specific parameter set signature algorithm
        Signature signer = Signature.getInstance(parameterSet, "Mozilla-JSS");
        testSignVerifyOperation(signer, keyPair, testData, parameterSet + " with " + description);

        // Test generic ML-DSA algorithm (should work with any parameter set key)
        Signature genericSigner = Signature.getInstance("ML-DSA", "Mozilla-JSS");
        testSignVerifyOperation(genericSigner, keyPair, testData, "ML-DSA with " + description);
    }

    /**
     * Perform actual sign and verify operations
     */
    private static void testSignVerifyOperation(Signature signer, KeyPair keyPair,
                                              byte[] testData, String context) throws Exception {

        if (!"Mozilla-JSS".equals(signer.getProvider().getName())) {
            throw new Exception("Expected Mozilla-JSS provider but got " +
                              signer.getProvider().getName() + " for " + context);
        }

        // Sign
        signer.initSign(keyPair.getPrivate());
        signer.update(testData);
        byte[] signature = signer.sign();

        if (signature == null || signature.length == 0) {
            throw new Exception("Signature generation failed for " + context);
        }

        // Verify with correct key
        signer.initVerify(keyPair.getPublic());
        signer.update(testData);
        boolean verified = signer.verify(signature);

        if (!verified) {
            throw new Exception("Signature verification failed for " + context);
        }

        // Test verification failure with wrong data
        signer.initVerify(keyPair.getPublic());
        byte[] wrongData = Arrays.copyOf(testData, testData.length);
        if (wrongData.length > 0) {
            wrongData[0] ^= 0x01; // Flip one bit
        }
        signer.update(wrongData);
        boolean shouldFail = signer.verify(signature);

        if (shouldFail) {
            throw new Exception("Signature verification should have failed with wrong data for " + context);
        }

        System.out.println("    ✓ " + context + " - signature size: " + signature.length + " bytes");
    }

    /**
     * Test that signatures are properly randomized (non-deterministic)
     */
    private static void testSignatureRandomness(String parameterSet, KeyPair keyPair) throws Exception {
        Signature signer = Signature.getInstance(parameterSet, "Mozilla-JSS");

        // Generate two signatures of the same data
        signer.initSign(keyPair.getPrivate());
        signer.update(TEST_DATA_SMALL);
        byte[] signature1 = signer.sign();

        signer.initSign(keyPair.getPrivate());
        signer.update(TEST_DATA_SMALL);
        byte[] signature2 = signer.sign();

        // Signatures should be different (due to randomness in ML-DSA)
        if (Arrays.equals(signature1, signature2)) {
            throw new Exception("ML-DSA signatures should be randomized but got identical signatures for " + parameterSet);
        }

        // But both should verify correctly
        signer.initVerify(keyPair.getPublic());
        signer.update(TEST_DATA_SMALL);
        if (!signer.verify(signature1)) {
            throw new Exception("First signature failed verification for " + parameterSet);
        }

        signer.initVerify(keyPair.getPublic());
        signer.update(TEST_DATA_SMALL);
        if (!signer.verify(signature2)) {
            throw new Exception("Second signature failed verification for " + parameterSet);
        }

        System.out.println("    ✓ Signature randomness test passed for " + parameterSet);
    }

    /**
     * Test that keys from different parameter sets are not cross-compatible
     */
    private static void testCrossParameterCompatibility() throws Exception {
        System.out.println("\n--- Testing Cross-Parameter Compatibility ---");

        // Generate keys for different parameter sets
        KeyPairGenerator kpg44 = KeyPairGenerator.getInstance("ML-DSA-44", "Mozilla-JSS");
        KeyPairGenerator kpg65 = KeyPairGenerator.getInstance("ML-DSA-65", "Mozilla-JSS");

        KeyPair kp44 = kpg44.generateKeyPair();
        KeyPair kp65 = kpg65.generateKeyPair();

        // Try to sign with one parameter set and verify with another (should fail)
        try {
            Signature signer = Signature.getInstance("ML-DSA-44", "Mozilla-JSS");
            signer.initSign(kp44.getPrivate());
            signer.update(TEST_DATA_SMALL);
            byte[] signature = signer.sign();

            // Try to verify with wrong key (different parameter set)
            signer.initVerify(kp65.getPublic());
            signer.update(TEST_DATA_SMALL);
            boolean result = signer.verify(signature);

            if (result) {
                throw new Exception("Cross-parameter verification should have failed but succeeded");
            }

            System.out.println("✓ Cross-parameter verification properly failed");

        } catch (InvalidKeyException | SignatureException e) {
            // This is expected - different parameter sets should not be compatible
            System.out.println("✓ Cross-parameter incompatibility properly detected: " + e.getMessage());
        }
    }

    /**
     * Test algorithm naming compliance with JEP 497
     */
    private static void testAlgorithmNaming() throws Exception {
        System.out.println("\n--- Testing Algorithm Naming Compliance ---");

        // Test that all standard names from JEP 497 are supported
        String[] requiredNames = {
            "ML-DSA",      // Generic algorithm
            "ML-DSA-44",   // Category 2 security
            "ML-DSA-65",   // Category 3 security
            "ML-DSA-87"    // Category 5 security
        };

        for (String algorithmName : requiredNames) {
            try {
                Signature sig = Signature.getInstance(algorithmName, "Mozilla-JSS");
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithmName, "Mozilla-JSS");

                System.out.println("✓ Algorithm name '" + algorithmName + "' is properly supported");

            } catch (NoSuchAlgorithmException e) {
                throw new Exception("Required algorithm name '" + algorithmName + "' is not supported", e);
            }
        }

        System.out.println("Algorithm naming compliance test passed");
    }

    /**
     * Test various error conditions and edge cases
     */
    private static void testErrorConditions() throws Exception {
        System.out.println("\n--- Testing Error Conditions ---");

        // Test invalid algorithm names
        try {
            Signature.getInstance("ML-DSA-INVALID", "Mozilla-JSS");
            throw new Exception("Should have failed with invalid algorithm name");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("✓ Invalid algorithm name properly rejected");
        }

        // Test signing with uninitialized signature
        try {
            Signature sig = Signature.getInstance("ML-DSA-44", "Mozilla-JSS");
            sig.sign(); // Should fail - not initialized
            throw new Exception("Should have failed with uninitialized signature");
        } catch (SignatureException e) {
            System.out.println("✓ Uninitialized signature properly rejected");
        }

        // Test verifying with uninitialized signature
        try {
            Signature sig = Signature.getInstance("ML-DSA-44", "Mozilla-JSS");
            sig.verify(new byte[100]); // Should fail - not initialized
            throw new Exception("Should have failed with uninitialized verification");
        } catch (SignatureException e) {
            System.out.println("✓ Uninitialized verification properly rejected");
        }

        // Test null data handling
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "Mozilla-JSS");
        KeyPair kp = kpg.generateKeyPair();
        Signature sig = Signature.getInstance("ML-DSA-44", "Mozilla-JSS");

        try {
            sig.initSign(kp.getPrivate());
            sig.update((byte[])null);
            throw new Exception("Should have failed with null data");
        } catch (NullPointerException | SignatureException e) {
            System.out.println("✓ Null data properly rejected");
        }

        System.out.println("Error condition testing completed");
    }
}