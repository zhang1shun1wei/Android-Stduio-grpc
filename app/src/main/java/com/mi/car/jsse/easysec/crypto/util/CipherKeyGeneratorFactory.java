package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.asn1.kisa.KISAObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.ntt.NTTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.generators.DESKeyGenerator;
import com.mi.car.jsse.easysec.crypto.generators.DESedeKeyGenerator;
import java.security.SecureRandom;

public class CipherKeyGeneratorFactory {
    private CipherKeyGeneratorFactory() {
    }

    public static CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random) throws IllegalArgumentException {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 128);
        }
        if (NISTObjectIdentifiers.id_aes192_CBC.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, BERTags.PRIVATE);
        }
        if (NISTObjectIdentifiers.id_aes256_CBC.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 256);
        }
        if (NISTObjectIdentifiers.id_aes128_GCM.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 128);
        }
        if (NISTObjectIdentifiers.id_aes192_GCM.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, BERTags.PRIVATE);
        }
        if (NISTObjectIdentifiers.id_aes256_GCM.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 256);
        }
        if (NISTObjectIdentifiers.id_aes128_CCM.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 128);
        }
        if (NISTObjectIdentifiers.id_aes192_CCM.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, BERTags.PRIVATE);
        }
        if (NISTObjectIdentifiers.id_aes256_CCM.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 256);
        }
        if (PKCSObjectIdentifiers.des_EDE3_CBC.equals((ASN1Primitive) algorithm)) {
            DESedeKeyGenerator keyGen = new DESedeKeyGenerator();
            keyGen.init(new KeyGenerationParameters(random, BERTags.PRIVATE));
            return keyGen;
        } else if (NTTObjectIdentifiers.id_camellia128_cbc.equals((ASN1Primitive) algorithm)) {
            return createCipherKeyGenerator(random, 128);
        } else {
            if (NTTObjectIdentifiers.id_camellia192_cbc.equals((ASN1Primitive) algorithm)) {
                return createCipherKeyGenerator(random, BERTags.PRIVATE);
            }
            if (NTTObjectIdentifiers.id_camellia256_cbc.equals((ASN1Primitive) algorithm)) {
                return createCipherKeyGenerator(random, 256);
            }
            if (KISAObjectIdentifiers.id_seedCBC.equals((ASN1Primitive) algorithm)) {
                return createCipherKeyGenerator(random, 128);
            }
            if (AlgorithmIdentifierFactory.CAST5_CBC.equals((ASN1Primitive) algorithm)) {
                return createCipherKeyGenerator(random, 128);
            }
            if (OIWObjectIdentifiers.desCBC.equals((ASN1Primitive) algorithm)) {
                DESKeyGenerator keyGen2 = new DESKeyGenerator();
                keyGen2.init(new KeyGenerationParameters(random, 64));
                return keyGen2;
            } else if (PKCSObjectIdentifiers.rc4.equals((ASN1Primitive) algorithm)) {
                return createCipherKeyGenerator(random, 128);
            } else {
                if (PKCSObjectIdentifiers.RC2_CBC.equals((ASN1Primitive) algorithm)) {
                    return createCipherKeyGenerator(random, 128);
                }
                throw new IllegalArgumentException("cannot recognise cipher: " + algorithm);
            }
        }
    }

    private static CipherKeyGenerator createCipherKeyGenerator(SecureRandom random, int keySize) {
        CipherKeyGenerator keyGen = new CipherKeyGenerator();
        keyGen.init(new KeyGenerationParameters(random, keySize));
        return keyGen;
    }
}
