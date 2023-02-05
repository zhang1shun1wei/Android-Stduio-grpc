package com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import com.mi.car.jsse.easysec.pqc.crypto.ExchangePair;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHAgreement;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHExchangePairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPublicKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.ShortBufferException;

public class KeyAgreementSpi extends BaseAgreementSpi {
    private NHAgreement agreement;
    private NHExchangePairGenerator exchangePairGenerator;
    private BCNHPublicKey otherPartyKey;
    private byte[] shared;

    public KeyAgreementSpi() {
        super("NH", null);
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.KeyAgreementSpi, com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseAgreementSpi
    public void engineInit(Key key, SecureRandom secureRandom) throws InvalidKeyException {
        if (key != null) {
            this.agreement = new NHAgreement();
            this.agreement.init(((BCNHPrivateKey) key).getKeyParams());
            return;
        }
        this.exchangePairGenerator = new NHExchangePairGenerator(secureRandom);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseAgreementSpi
    public void doInitFromKey(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("NewHope does not require parameters");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.KeyAgreementSpi
    public Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (!lastPhase) {
            throw new IllegalStateException("NewHope can only be between two parties.");
        }
        this.otherPartyKey = (BCNHPublicKey) key;
        if (this.exchangePairGenerator != null) {
            ExchangePair exchPair = this.exchangePairGenerator.generateExchange((AsymmetricKeyParameter) this.otherPartyKey.getKeyParams());
            this.shared = exchPair.getSharedValue();
            return new BCNHPublicKey((NHPublicKeyParameters) exchPair.getPublicKey());
        }
        this.shared = this.agreement.calculateAgreement(this.otherPartyKey.getKeyParams());
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.KeyAgreementSpi, com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseAgreementSpi
    public byte[] engineGenerateSecret() throws IllegalStateException {
        byte[] rv = Arrays.clone(this.shared);
        Arrays.fill(this.shared, (byte) 0);
        return rv;
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.KeyAgreementSpi, com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseAgreementSpi
    public int engineGenerateSecret(byte[] bytes, int offset) throws IllegalStateException, ShortBufferException {
        System.arraycopy(this.shared, 0, bytes, offset, this.shared.length);
        Arrays.fill(this.shared, (byte) 0);
        return this.shared.length;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseAgreementSpi
    public byte[] doCalcSecret() {
        return engineGenerateSecret();
    }
}
