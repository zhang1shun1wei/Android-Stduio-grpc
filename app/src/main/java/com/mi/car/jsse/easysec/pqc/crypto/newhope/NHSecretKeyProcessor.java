package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.crypto.ExchangePair;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class NHSecretKeyProcessor {
    private final Xof xof;

    public static class PartyUBuilder {
        private final AsymmetricCipherKeyPair aKp;
        private final NHAgreement agreement = new NHAgreement();
        private byte[] sharedInfo = null;
        private boolean used = false;

        public PartyUBuilder(SecureRandom random) {
            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();
            kpGen.init(new KeyGenerationParameters(random, 2048));
            this.aKp = kpGen.generateKeyPair();
            this.agreement.init(this.aKp.getPrivate());
        }

        public PartyUBuilder withSharedInfo(byte[] sharedInfo2) {
            this.sharedInfo = Arrays.clone(sharedInfo2);
            return this;
        }

        public byte[] getPartA() {
            return ((NHPublicKeyParameters) this.aKp.getPublic()).getPubData();
        }

        public NHSecretKeyProcessor build(byte[] partB) {
            if (this.used) {
                throw new IllegalStateException("builder already used");
            }
            this.used = true;
            return new NHSecretKeyProcessor(this.agreement.calculateAgreement(new NHPublicKeyParameters(partB)), this.sharedInfo);
        }
    }

    public static class PartyVBuilder {
        protected final SecureRandom random;
        private byte[] sharedInfo = null;
        private byte[] sharedSecret = null;
        private boolean used = false;

        public PartyVBuilder(SecureRandom random2) {
            this.random = random2;
        }

        public PartyVBuilder withSharedInfo(byte[] sharedInfo2) {
            this.sharedInfo = Arrays.clone(sharedInfo2);
            return this;
        }

        public byte[] getPartB(byte[] partUContribution) {
            ExchangePair bEp = new NHExchangePairGenerator(this.random).generateExchange(new NHPublicKeyParameters(partUContribution));
            this.sharedSecret = bEp.getSharedValue();
            return ((NHPublicKeyParameters) bEp.getPublicKey()).getPubData();
        }

        public NHSecretKeyProcessor build() {
            if (this.used) {
                throw new IllegalStateException("builder already used");
            }
            this.used = true;
            return new NHSecretKeyProcessor(this.sharedSecret, this.sharedInfo);
        }
    }

    private NHSecretKeyProcessor(byte[] secret, byte[] shared) {
        this.xof = new SHAKEDigest(256);
        this.xof.update(secret, 0, secret.length);
        if (shared != null) {
            this.xof.update(shared, 0, shared.length);
        }
        Arrays.fill(secret, (byte) 0);
    }

    public byte[] processKey(byte[] initialKey) {
        byte[] xorBytes = new byte[initialKey.length];
        this.xof.doFinal(xorBytes, 0, xorBytes.length);
        xor(initialKey, xorBytes);
        Arrays.fill(xorBytes, (byte) 0);
        return initialKey;
    }

    private static void xor(byte[] a, byte[] b) {
        for (int i = 0; i != a.length; i++) {
            a[i] = (byte) (a[i] ^ b[i]);
        }
    }
}
