package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.util.DEROtherInfo;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.crypto.ExchangePair;
import java.io.IOException;
import java.security.SecureRandom;

public class NHOtherInfoGenerator {
    protected final DEROtherInfo.Builder otherInfoBuilder;
    protected final SecureRandom random;
    protected boolean used = false;

    public NHOtherInfoGenerator(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random2) {
        this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
        this.random = random2;
    }

    public static class PartyU extends NHOtherInfoGenerator {
        private AsymmetricCipherKeyPair aKp;
        private NHAgreement agreement = new NHAgreement();

        public PartyU(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random) {
            super(algorithmID, partyUInfo, partyVInfo, random);
            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();
            kpGen.init(new KeyGenerationParameters(random, 2048));
            this.aKp = kpGen.generateKeyPair();
            this.agreement.init(this.aKp.getPrivate());
        }

        public NHOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo) {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);
            return this;
        }

        public byte[] getSuppPrivInfoPartA() {
            return NHOtherInfoGenerator.getEncoded((NHPublicKeyParameters) this.aKp.getPublic());
        }

        public DEROtherInfo generate(byte[] suppPrivInfoPartB) {
            if (this.used) {
                throw new IllegalStateException("builder already used");
            }
            this.used = true;
            this.otherInfoBuilder.withSuppPrivInfo(this.agreement.calculateAgreement(NHOtherInfoGenerator.getPublicKey(suppPrivInfoPartB)));
            return this.otherInfoBuilder.build();
        }
    }

    public static class PartyV extends NHOtherInfoGenerator {
        public PartyV(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random) {
            super(algorithmID, partyUInfo, partyVInfo, random);
        }

        public NHOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo) {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);
            return this;
        }

        public byte[] getSuppPrivInfoPartB(byte[] suppPrivInfoPartA) {
            ExchangePair bEp = new NHExchangePairGenerator(this.random).generateExchange(NHOtherInfoGenerator.getPublicKey(suppPrivInfoPartA));
            this.otherInfoBuilder.withSuppPrivInfo(bEp.getSharedValue());
            return NHOtherInfoGenerator.getEncoded((NHPublicKeyParameters) bEp.getPublicKey());
        }

        public DEROtherInfo generate() {
            if (this.used) {
                throw new IllegalStateException("builder already used");
            }
            this.used = true;
            return this.otherInfoBuilder.build();
        }
    }

    /* access modifiers changed from: private */
    public static byte[] getEncoded(NHPublicKeyParameters pubKey) {
        try {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.newHope), pubKey.getPubData()).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    /* access modifiers changed from: private */
    public static NHPublicKeyParameters getPublicKey(byte[] enc) {
        return new NHPublicKeyParameters(SubjectPublicKeyInfo.getInstance(enc).getPublicKeyData().getOctets());
    }
}
