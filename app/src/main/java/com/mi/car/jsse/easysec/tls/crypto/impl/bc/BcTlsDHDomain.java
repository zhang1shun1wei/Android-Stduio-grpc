package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.agreement.DHBasicAgreement;
import com.mi.car.jsse.easysec.crypto.generators.DHBasicKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.params.DHKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.tls.TlsDHUtils;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.DHGroup;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHDomain;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.io.IOException;
import java.math.BigInteger;

public class BcTlsDHDomain implements TlsDHDomain {
    protected TlsDHConfig config;
    protected BcTlsCrypto crypto;
    protected DHParameters domainParameters;

    private static byte[] encodeValue(DHParameters dh, boolean padded, BigInteger x) {
        if (padded) {
            return BigIntegers.asUnsignedByteArray(getValueLength(dh), x);
        }
        return BigIntegers.asUnsignedByteArray(x);
    }

    private static int getValueLength(DHParameters dh) {
        return (dh.getP().bitLength() + 7) / 8;
    }

    public static BcTlsSecret calculateDHAgreement(BcTlsCrypto crypto2, DHPrivateKeyParameters privateKey, DHPublicKeyParameters publicKey, boolean padded) {
        DHBasicAgreement basicAgreement = new DHBasicAgreement();
        basicAgreement.init(privateKey);
        return crypto2.adoptLocalSecret(encodeValue(privateKey.getParameters(), padded, basicAgreement.calculateAgreement(publicKey)));
    }

    public static DHParameters getDomainParameters(TlsDHConfig dhConfig) {
        DHGroup dhGroup = TlsDHUtils.getDHGroup(dhConfig);
        if (dhGroup != null) {
            return new DHParameters(dhGroup.getP(), dhGroup.getG(), dhGroup.getQ(), dhGroup.getL());
        }
        throw new IllegalArgumentException("No DH configuration provided");
    }

    public BcTlsDHDomain(BcTlsCrypto crypto2, TlsDHConfig dhConfig) {
        this.crypto = crypto2;
        this.config = dhConfig;
        this.domainParameters = getDomainParameters(dhConfig);
    }

    public BcTlsSecret calculateDHAgreement(DHPrivateKeyParameters privateKey, DHPublicKeyParameters publicKey) {
        return calculateDHAgreement(this.crypto, privateKey, publicKey, this.config.isPadded());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsDHDomain
    public TlsAgreement createDH() {
        return new BcTlsDH(this);
    }

    public BigInteger decodeParameter(byte[] encoding) throws IOException {
        if (!this.config.isPadded() || getValueLength(this.domainParameters) == encoding.length) {
            return new BigInteger(1, encoding);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public DHPublicKeyParameters decodePublicKey(byte[] encoding) throws IOException {
        try {
            return new DHPublicKeyParameters(decodeParameter(encoding), this.domainParameters);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 40, (Throwable) e);
        }
    }

    public byte[] encodeParameter(BigInteger x) {
        return encodeValue(this.domainParameters, this.config.isPadded(), x);
    }

    public byte[] encodePublicKey(DHPublicKeyParameters publicKey) {
        return encodeValue(this.domainParameters, true, publicKey.getY());
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        DHBasicKeyPairGenerator keyPairGenerator = new DHBasicKeyPairGenerator();
        keyPairGenerator.init(new DHKeyGenerationParameters(this.crypto.getSecureRandom(), this.domainParameters));
        return keyPairGenerator.generateKeyPair();
    }
}
