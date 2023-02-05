package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.gm.GMObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Integers;
import java.util.HashMap;
import java.util.Map;

public class PBKDF2Config extends PBKDFConfig {
    private static final Map PRFS_SALT = new HashMap();
    public static final AlgorithmIdentifier PRF_SHA1 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);
    public static final AlgorithmIdentifier PRF_SHA256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE);
    public static final AlgorithmIdentifier PRF_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_256, DERNull.INSTANCE);
    public static final AlgorithmIdentifier PRF_SHA3_512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, DERNull.INSTANCE);
    public static final AlgorithmIdentifier PRF_SHA512 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
    private final int iterationCount;
    private final AlgorithmIdentifier prf;
    private final int saltLength;

    static {
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA1, Integers.valueOf(20));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA256, Integers.valueOf(32));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA512, Integers.valueOf(64));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA224, Integers.valueOf(28));
        PRFS_SALT.put(PKCSObjectIdentifiers.id_hmacWithSHA384, Integers.valueOf(48));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_224, Integers.valueOf(28));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, Integers.valueOf(32));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, Integers.valueOf(48));
        PRFS_SALT.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, Integers.valueOf(64));
        PRFS_SALT.put(CryptoProObjectIdentifiers.gostR3411Hmac, Integers.valueOf(32));
        PRFS_SALT.put(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_256, Integers.valueOf(32));
        PRFS_SALT.put(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_512, Integers.valueOf(64));
        PRFS_SALT.put(GMObjectIdentifiers.hmac_sm3, Integers.valueOf(32));
    }

    static int getSaltSize(ASN1ObjectIdentifier algorithm) {
        if (PRFS_SALT.containsKey(algorithm)) {
            return ((Integer) PRFS_SALT.get(algorithm)).intValue();
        }
        throw new IllegalStateException("no salt size for algorithm: " + algorithm);
    }

    public static class Builder {
        private int iterationCount = 1024;
        private AlgorithmIdentifier prf = PBKDF2Config.PRF_SHA1;
        private int saltLength = -1;

        public Builder withIterationCount(int iterationCount2) {
            this.iterationCount = iterationCount2;
            return this;
        }

        public Builder withPRF(AlgorithmIdentifier prf2) {
            this.prf = prf2;
            return this;
        }

        public Builder withSaltLength(int saltLength2) {
            this.saltLength = saltLength2;
            return this;
        }

        public PBKDF2Config build() {
            return new PBKDF2Config(this);
        }
    }

    private PBKDF2Config(Builder builder) {
        super(PKCSObjectIdentifiers.id_PBKDF2);
        this.iterationCount = builder.iterationCount;
        this.prf = builder.prf;
        if (builder.saltLength < 0) {
            this.saltLength = getSaltSize(this.prf.getAlgorithm());
        } else {
            this.saltLength = builder.saltLength;
        }
    }

    public int getIterationCount() {
        return this.iterationCount;
    }

    public AlgorithmIdentifier getPRF() {
        return this.prf;
    }

    public int getSaltLength() {
        return this.saltLength;
    }
}
