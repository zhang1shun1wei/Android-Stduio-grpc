package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.CipherSuite;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

class CipherSuiteInfo {
    private final int cipherSuite;
    private final String name;
    private final boolean isTLSv13;
    private final Set<String> decompositionTLS;
    private final Set<String> decompositionX509;

    static CipherSuiteInfo forCipherSuite(int cipherSuite, String name) {
        if (!name.startsWith("TLS_")) {
            throw new IllegalArgumentException();
        } else {
            int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(cipherSuite);
            int encryptionAlgorithmType = TlsUtils.getEncryptionAlgorithmType(encryptionAlgorithm);
            int cryptoHashAlgorithm = getCryptoHashAlgorithm(cipherSuite);
            int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
            int macAlgorithm = TlsUtils.getMACAlgorithm(cipherSuite);
            Set<String> decompositionX509 = new HashSet();
            decomposeKeyExchangeAlgorithm(decompositionX509, keyExchangeAlgorithm);
            Set<String> decompositionTLS = new HashSet(decompositionX509);
            decomposeKeyExchangeAlgorithmTLS(decompositionTLS, keyExchangeAlgorithm);
            decomposeEncryptionAlgorithm(decompositionTLS, encryptionAlgorithm);
            decomposeHashAlgorithm(decompositionTLS, cryptoHashAlgorithm);
            decomposeMACAlgorithm(decompositionTLS, encryptionAlgorithmType, macAlgorithm);
            boolean isTLSv13 = 0 == keyExchangeAlgorithm;
            return new CipherSuiteInfo(cipherSuite, name, isTLSv13, Collections.unmodifiableSet(decompositionTLS), Collections.unmodifiableSet(decompositionX509));
        }
    }

    private CipherSuiteInfo(int cipherSuite, String name, boolean isTLSv13, Set<String> decompositionTLS, Set<String> decompositionX509) {
        this.cipherSuite = cipherSuite;
        this.name = name;
        this.isTLSv13 = isTLSv13;
        this.decompositionTLS = decompositionTLS;
        this.decompositionX509 = decompositionX509;
    }

    public int getCipherSuite() {
        return this.cipherSuite;
    }

    public Set<String> getDecompositionTLS() {
        return this.decompositionTLS;
    }

    public Set<String> getDecompositionX509() {
        return this.decompositionX509;
    }

    public String getName() {
        return this.name;
    }

    boolean isTLSv13() {
        return this.isTLSv13;
    }

    private static void addAll(Set<String> decomposition, String... entries) {
        String[] var2 = entries;
        int var3 = entries.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            String entry = var2[var4];
            decomposition.add(entry);
        }

    }

    private static void decomposeEncryptionAlgorithm(Set<String> decomposition, int encryptionAlgorithm) {
        String transformation = getTransformation(encryptionAlgorithm);
        decomposition.addAll(JcaAlgorithmDecomposer.INSTANCE_JCA.decompose(transformation));
        switch(encryptionAlgorithm) {
            case 0:
                decomposition.add("C_NULL");
                break;
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 14:
            default:
                throw new IllegalArgumentException();
            case 7:
                decomposition.add("3DES_EDE_CBC");
                break;
            case 8:
                decomposition.add("AES_128_CBC");
                break;
            case 9:
                decomposition.add("AES_256_CBC");
                break;
            case 10:
                decomposition.add("AES_128_GCM");
                break;
            case 11:
                decomposition.add("AES_256_GCM");
                break;
            case 12:
                decomposition.add("CAMELLIA_128_CBC");
                break;
            case 13:
                decomposition.add("CAMELLIA_256_CBC");
                break;
            case 15:
                decomposition.add("AES_128_CCM");
                break;
            case 16:
                decomposition.add("AES_128_CCM_8");
                break;
            case 17:
                decomposition.add("AES_256_CCM");
                break;
            case 18:
                decomposition.add("AES_256_CCM_8");
                break;
            case 19:
                decomposition.add("CAMELLIA_128_GCM");
                break;
            case 20:
                decomposition.add("CAMELLIA_256_GCM");
            case 21:
                break;
            case 22:
                decomposition.add("ARIA_128_CBC");
                break;
            case 23:
                decomposition.add("ARIA_256_CBC");
                break;
            case 24:
                decomposition.add("ARIA_128_GCM");
                break;
            case 25:
                decomposition.add("ARIA_256_GCM");
                break;
            case 26:
                decomposition.add("SM4_CCM");
                break;
            case 27:
                decomposition.add("SM4_GCM");
                break;
            case 28:
                decomposition.add("SM4_CBC");
        }

    }

    private static void decomposeHashAlgorithm(Set<String> decomposition, int cryptoHashAlgorithm) {
        switch(cryptoHashAlgorithm) {
            case 4:
                addAll(decomposition, "SHA256", "SHA-256", "HmacSHA256");
                break;
            case 5:
                addAll(decomposition, "SHA384", "SHA-384", "HmacSHA384");
                break;
            case 6:
            default:
                throw new IllegalArgumentException();
            case 7:
                addAll(decomposition, "SM3", "HmacSM3");
        }

    }

    private static void decomposeKeyExchangeAlgorithm(Set<String> decomposition, int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 0:
            case 11:
            case 20:
                break;
            case 1:
                addAll(decomposition, "RSA");
                break;
            case 2:
            case 4:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 18:
            default:
                throw new IllegalArgumentException();
            case 3:
                addAll(decomposition, "DSA", "DSS", "DH", "DHE", "DiffieHellman", "DHE_DSS");
                break;
            case 5:
                addAll(decomposition, "RSA", "DH", "DHE", "DiffieHellman", "DHE_RSA");
                break;
            case 17:
                addAll(decomposition, "ECDHE", "ECDSA", "ECDHE_ECDSA");
                break;
            case 19:
                addAll(decomposition, "ECDHE", "RSA", "ECDHE_RSA");
        }

    }

    private static void decomposeKeyExchangeAlgorithmTLS(Set<String> decompositionTLS, int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 0:
                addAll(decompositionTLS, "K_NULL");
            case 1:
            case 3:
            case 5:
            case 17:
            case 19:
                break;
            case 2:
            case 4:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 18:
            default:
                throw new IllegalArgumentException();
            case 11:
                addAll(decompositionTLS, "ANON", "DH", "DiffieHellman", "DH_ANON");
                break;
            case 20:
                addAll(decompositionTLS, "ANON", "ECDH", "ECDH_ANON");
        }

    }

    private static void decomposeMACAlgorithm(Set<String> decomposition, int cipherType, int macAlgorithm) {
        switch(macAlgorithm) {
            case 0:
                if (2 != cipherType) {
                    addAll(decomposition, "M_NULL");
                }
                break;
            case 1:
                addAll(decomposition, "MD5", "HmacMD5");
                break;
            case 2:
                addAll(decomposition, "SHA1", "SHA-1", "HmacSHA1");
                break;
            case 3:
                addAll(decomposition, "SHA256", "SHA-256", "HmacSHA256");
                break;
            case 4:
                addAll(decomposition, "SHA384", "SHA-384", "HmacSHA384");
                break;
            default:
                throw new IllegalArgumentException();
        }

    }

    private static int getCryptoHashAlgorithm(int cipherSuite) {
        switch(cipherSuite) {
            case 2:
            case 10:
            case 19:
            case 22:
            case 47:
            case 50:
            case 51:
            case 53:
            case 56:
            case 57:
            case 65:
            case 68:
            case 69:
            case 132:
            case 135:
            case 136:
            case 49158:
            case 49160:
            case 49161:
            case 49162:
            case 49168:
            case 49170:
            case 49171:
            case 49172:
                return 4;
            case 59:
            case 60:
            case 61:
            case 64:
            case 103:
            case 106:
            case 107:
            case 156:
            case 158:
            case 162:
            case 186:
            case 189:
            case 190:
            case 192:
            case 195:
            case 196:
            case 4865:
            case 4867:
            case 4868:
            case 4869:
            case 49187:
            case 49191:
            case 49195:
            case 49199:
            case 49212:
            case 49218:
            case 49220:
            case 49224:
            case 49228:
            case 49232:
            case 49234:
            case 49238:
            case 49244:
            case 49248:
            case 49266:
            case 49270:
            case 49274:
            case 49276:
            case 49280:
            case 49286:
            case 49290:
            case 49308:
            case 49309:
            case 49310:
            case 49311:
            case 49312:
            case 49313:
            case 49314:
            case 49315:
            case 49324:
            case 49325:
            case 49326:
            case 49327:
            case 52392:
            case 52393:
            case 52394:
                return 4;
            case 157:
            case 159:
            case 163:
            case 4866:
            case 49188:
            case 49192:
            case 49196:
            case 49200:
            case 49213:
            case 49219:
            case 49221:
            case 49225:
            case 49229:
            case 49233:
            case 49235:
            case 49239:
            case 49245:
            case 49249:
            case 49267:
            case 49271:
            case 49275:
            case 49277:
            case 49281:
            case 49287:
            case 49291:
                return 5;
            case 198:
            case 199:
                return 7;
            default:
                throw new IllegalArgumentException();
        }
    }

    private static String getTransformation(int encryptionAlgorithm) {
        switch(encryptionAlgorithm) {
            case 0:
                return "NULL";
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 14:
            default:
                throw new IllegalArgumentException();
            case 7:
                return "DESede/CBC/NoPadding";
            case 8:
            case 9:
                return "AES/CBC/NoPadding";
            case 10:
            case 11:
                return "AES/GCM/NoPadding";
            case 12:
            case 13:
                return "Camellia/CBC/NoPadding";
            case 15:
            case 16:
            case 17:
            case 18:
                return "AES/CCM/NoPadding";
            case 19:
            case 20:
                return "Camellia/GCM/NoPadding";
            case 21:
                return "ChaCha20-Poly1305";
            case 22:
            case 23:
                return "ARIA/CBC/NoPadding";
            case 24:
            case 25:
                return "ARIA/GCM/NoPadding";
            case 26:
                return "SM4/CCM/NoPadding";
            case 27:
                return "SM4/GCM/NoPadding";
            case 28:
                return "SM4/CBC/NoPadding";
        }
    }
}