/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.algorithms;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Element;


/**
 * This class maps algorithm identifier URIs to JAVA JCE class names.
 */
public class JCEMapper {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(JCEMapper.class);

    private static Map<String, Algorithm> algorithmsMap = new ConcurrentHashMap<>();

    private static String providerName;

    /**
     * Method register
     *
     * @param id
     * @param algorithm
     * @throws SecurityException if a security manager is installed and the
     *    caller does not have permission to register the JCE algorithm
     */
    public static void register(String id, Algorithm algorithm) {
        JavaUtils.checkRegisterPermission();
        algorithmsMap.put(id, algorithm);
    }

    /**
     * This method registers the default algorithms.
     */
    public static void registerDefaultAlgorithms() {
        // Digest algorithms
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5,
            new Algorithm("", "MD5", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160,
            new Algorithm("", "RIPEMD160", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1,
            new Algorithm("", "SHA-1", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224,
            new Algorithm("", "SHA-224", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256,
            new Algorithm("", "SHA-256", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384,
            new Algorithm("", "SHA-384", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512,
            new Algorithm("", "SHA-512", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_WHIRLPOOL,
            new Algorithm("", "WHIRLPOOL", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_224,
            new Algorithm("", "SHA3-224", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256,
            new Algorithm("", "SHA3-256", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384,
            new Algorithm("", "SHA3-384", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_512,
            new Algorithm("", "SHA3-512", "MessageDigest")
        );
        algorithmsMap.put(
            MessageDigestAlgorithm.ALGO_ID_DIGEST_SM3,
            new Algorithm("", "SM3", "MessageDigest")
        );
        // Signature algorithms
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_DSA,
            new Algorithm("DSA", "SHA1withDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_DSA_SHA256,
            new Algorithm("DSA", "SHA256withDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5,
            new Algorithm("RSA", "MD5withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_RIPEMD160,
            new Algorithm("RSA", "RIPEMD160withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
            new Algorithm("RSA", "SHA1withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224,
            new Algorithm("RSA", "SHA224withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
            new Algorithm("RSA", "SHA256withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384,
            new Algorithm("RSA", "SHA384withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512,
            new Algorithm("RSA", "SHA512withRSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1,
            new Algorithm("RSA", "SHA1withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1,
            new Algorithm("RSA", "SHA224withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
            new Algorithm("RSA", "SHA256withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1,
            new Algorithm("RSA", "SHA384withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1,
            new Algorithm("RSA", "SHA512withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
             XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1,
             new Algorithm("RSA", "SHA3-224withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
             XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1,
             new Algorithm("RSA", "SHA3-256withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
             XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1,
             new Algorithm("RSA", "SHA3-384withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
             XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1,
             new Algorithm("RSA", "SHA3-512withRSAandMGF1", "Signature")
        );
        algorithmsMap.put(
             XMLSignature.ALGO_ID_SIGNATURE_RSA_PSS,
             new Algorithm("RSA", "RSASSA-PSS", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1,
            new Algorithm("EC", "SHA1withECDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA224,
            new Algorithm("EC", "SHA224withECDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
            new Algorithm("EC", "SHA256withECDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384,
            new Algorithm("EC", "SHA384withECDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512,
            new Algorithm("EC", "SHA512withECDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_RIPEMD160,
            new Algorithm("EC", "RIPEMD160withECDSA", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED25519,
            new Algorithm("Ed25519", "Ed25519", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED448,
            new Algorithm("Ed448", "Ed448", "Signature")
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5,
            new Algorithm("", "HmacMD5", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_RIPEMD160,
            new Algorithm("", "HMACRIPEMD160", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_SHA1,
            new Algorithm("", "HmacSHA1", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_SHA224,
            new Algorithm("", "HmacSHA224", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_SHA256,
            new Algorithm("", "HmacSHA256", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_SHA384,
            new Algorithm("", "HmacSHA384", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_SHA512,
            new Algorithm("", "HmacSHA512", "Mac", 0, 0)
        );
        algorithmsMap.put(
            XMLSignature.ALGO_ID_MAC_HMAC_SM3,
            new Algorithm("", "HmacSM3", "Mac", 0, 0)
        );
        // Encryption algorithms
        algorithmsMap.put(
            XMLCipher.TRIPLEDES,
            new Algorithm("DESede", "DESede/CBC/ISO10126Padding", "BlockEncryption", 192, 64)
        );
        algorithmsMap.put(
            XMLCipher.AES_128,
            new Algorithm("AES", "AES/CBC/ISO10126Padding", "BlockEncryption", 128, 128)
        );
        algorithmsMap.put(
            XMLCipher.AES_192,
            new Algorithm("AES", "AES/CBC/ISO10126Padding", "BlockEncryption", 192, 128)
        );
        algorithmsMap.put(
            XMLCipher.AES_256,
            new Algorithm("AES", "AES/CBC/ISO10126Padding", "BlockEncryption", 256, 128)
        );
        algorithmsMap.put(
            XMLCipher.AES_128_GCM,
            new Algorithm("AES", "AES/GCM/NoPadding", "BlockEncryption", 128, 96)
        );
        algorithmsMap.put(
            XMLCipher.AES_192_GCM,
            new Algorithm("AES", "AES/GCM/NoPadding", "BlockEncryption", 192, 96)
        );
        algorithmsMap.put(
            XMLCipher.AES_256_GCM,
            new Algorithm("AES", "AES/GCM/NoPadding", "BlockEncryption", 256, 96)
        );
        algorithmsMap.put(
            XMLCipher.SEED_128,
            new Algorithm("SEED", "SEED/CBC/ISO10126Padding", "BlockEncryption", 128, 128)
        );
        algorithmsMap.put(
            XMLCipher.CAMELLIA_128,
            new Algorithm("Camellia", "Camellia/CBC/ISO10126Padding", "BlockEncryption", 128, 128)
        );
        algorithmsMap.put(
            XMLCipher.CAMELLIA_192,
            new Algorithm("Camellia", "Camellia/CBC/ISO10126Padding", "BlockEncryption", 192, 128)
        );
        algorithmsMap.put(
            XMLCipher.CAMELLIA_256,
            new Algorithm("Camellia", "Camellia/CBC/ISO10126Padding", "BlockEncryption", 256, 128)
        );
        algorithmsMap.put(
            XMLCipher.RSA_v1dot5,
            new Algorithm("RSA", "RSA/ECB/PKCS1Padding", "KeyTransport")
        );
        algorithmsMap.put(
            XMLCipher.RSA_OAEP,
            new Algorithm("RSA", "RSA/ECB/OAEPPadding", "KeyTransport")
        );
        algorithmsMap.put(
            XMLCipher.RSA_OAEP_11,
            new Algorithm("RSA", "RSA/ECB/OAEPPadding", "KeyTransport")
        );
        algorithmsMap.put(
            XMLCipher.DIFFIE_HELLMAN,
            new Algorithm("", "", "KeyAgreement")
        );
        algorithmsMap.put(
            XMLCipher.TRIPLEDES_KeyWrap,
            new Algorithm("DESede", "DESedeWrap", "SymmetricKeyWrap", 192, 0)
        );
        algorithmsMap.put(
            XMLCipher.AES_128_KeyWrap,
            new Algorithm("AES", "AESWrap", "SymmetricKeyWrap", 128, 0)
        );
        algorithmsMap.put(
            XMLCipher.AES_192_KeyWrap,
            new Algorithm("AES", "AESWrap", "SymmetricKeyWrap", 192, 0)
        );
        algorithmsMap.put(
            XMLCipher.AES_256_KeyWrap,
            new Algorithm("AES", "AESWrap", "SymmetricKeyWrap", 256, 0)
        );
        algorithmsMap.put(
            XMLCipher.CAMELLIA_128_KeyWrap,
            new Algorithm("Camellia", "CamelliaWrap", "SymmetricKeyWrap", 128, 0)
        );
        algorithmsMap.put(
            XMLCipher.CAMELLIA_192_KeyWrap,
            new Algorithm("Camellia", "CamelliaWrap", "SymmetricKeyWrap", 192, 0)
        );
        algorithmsMap.put(
            XMLCipher.CAMELLIA_256_KeyWrap,
            new Algorithm("Camellia", "CamelliaWrap", "SymmetricKeyWrap", 256, 0)
        );
        algorithmsMap.put(
            XMLCipher.SEED_128_KeyWrap,
            new Algorithm("SEED", "SEEDWrap", "SymmetricKeyWrap", 128, 0)
        );
    }

    /**
     * Method translateURItoJCEID
     *
     * @param algorithmURI
     * @return the JCE standard name corresponding to the given URI
     */
    public static String translateURItoJCEID(String algorithmURI) {
        Algorithm algorithm = getAlgorithm(algorithmURI);
        if (algorithm != null) {
            return algorithm.jceName;
        }
        return null;
    }

    /**
     * Method getAlgorithmClassFromURI
     * @param algorithmURI
     * @return the class name that implements this algorithm
     */
    public static String getAlgorithmClassFromURI(String algorithmURI) {
        Algorithm algorithm = getAlgorithm(algorithmURI);
        if (algorithm != null) {
            return algorithm.algorithmClass;
        }
        return null;
    }

    /**
     * Returns the keylength in bits for a particular algorithm.
     *
     * @param algorithmURI
     * @return The length of the key used in the algorithm
     */
    public static int getKeyLengthFromURI(String algorithmURI) {
        Algorithm algorithm = getAlgorithm(algorithmURI);
        if (algorithm != null) {
            return algorithm.keyLength;
        }
        return 0;
    }

    public static int getIVLengthFromURI(String algorithmURI) {
        Algorithm algorithm = getAlgorithm(algorithmURI);
        if (algorithm != null) {
            return algorithm.ivLength;
        }
        return 0;
    }

    /**
     * Method getJCEKeyAlgorithmFromURI
     *
     * @param algorithmURI
     * @return The KeyAlgorithm for the given URI.
     */
    public static String getJCEKeyAlgorithmFromURI(String algorithmURI) {
        Algorithm algorithm = getAlgorithm(algorithmURI);
         if (algorithm != null) {
             return algorithm.requiredKey;
         }
        return null;
    }

    /**
     * Method getJCEProviderFromURI
     *
     * @param algorithmURI
     * @return The JCEProvider for the given URI.
     */
    public static String getJCEProviderFromURI(String algorithmURI) {
        Algorithm algorithm = getAlgorithm(algorithmURI);
        if (algorithm != null) {
            return algorithm.jceProvider;
        }
        return null;
    }

    /**
     * Method getAlgorithm
     *
     * @param algorithmURI
     * @return The Algorithm object for the given URI.
     */
    private static Algorithm getAlgorithm(String algorithmURI) {
        LOG.debug("Request for URI {}", algorithmURI);

        if (algorithmURI != null) {
            return algorithmsMap.get(algorithmURI);
        }
        return null;
    }

    /**
     * Gets the default Provider for obtaining the security algorithms
     * @return the default providerId.
     */
    public static String getProviderId() {
        return providerName;
    }

    /**
     * Sets the default Provider for obtaining the security algorithms
     * @param provider the default providerId.
     * @throws SecurityException if a security manager is installed and the
     *    caller does not have permission to register the JCE algorithm
     */
    public static void setProviderId(String provider) {
        JavaUtils.checkRegisterPermission();
        providerName = provider;
    }

    /**
     * Represents the Algorithm xml element
     */
    public static class Algorithm {

        final String requiredKey;
        final String jceName;
        final String algorithmClass;
        final int keyLength;
        final int ivLength;
        final String jceProvider;

        /**
         * Gets data from element
         * @param el
         */
        public Algorithm(Element el) {
            requiredKey = el.getAttributeNS(null, "RequiredKey");
            jceName = el.getAttributeNS(null, "JCEName");
            algorithmClass = el.getAttributeNS(null, "AlgorithmClass");
            jceProvider = el.getAttributeNS(null, "JCEProvider");
            if (el.hasAttribute("KeyLength")) {
                keyLength = Integer.parseInt(el.getAttributeNS(null, "KeyLength"));
            } else {
                keyLength = 0;
            }
            if (el.hasAttribute("IVLength")) {
                ivLength = Integer.parseInt(el.getAttributeNS(null, "IVLength"));
            } else {
                ivLength = 0;
            }
        }

        public Algorithm(String requiredKey, String jceName) {
            this(requiredKey, jceName, null, 0, 0);
        }

        public Algorithm(String requiredKey, String jceName, String algorithmClass) {
            this(requiredKey, jceName, algorithmClass, 0, 0);
        }

        public Algorithm(String requiredKey, String jceName, int keyLength) {
            this(requiredKey, jceName, null, keyLength, 0);
        }

        public Algorithm(String requiredKey, String jceName, String algorithmClass, int keyLength, int ivLength) {
            this(requiredKey, jceName, algorithmClass, keyLength, ivLength, null);
        }

        public Algorithm(String requiredKey, String jceName,
                         String algorithmClass, int keyLength, int ivLength, String jceProvider) {
            this.requiredKey = requiredKey;
            this.jceName = jceName;
            this.algorithmClass = algorithmClass;
            this.keyLength = keyLength;
            this.ivLength = ivLength;
            this.jceProvider = jceProvider;
        }
    }
}
