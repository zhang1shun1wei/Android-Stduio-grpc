package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.agreement.ECDHBasicAgreement;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import com.mi.car.jsse.easysec.crypto.generators.ECKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECDomain;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.io.IOException;

public class BcTlsECDomain implements TlsECDomain {
    protected final TlsECConfig config;
    protected final BcTlsCrypto crypto;
    protected final ECDomainParameters domainParameters;

    public static BcTlsSecret calculateECDHAgreement(BcTlsCrypto crypto2, ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey) {
        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init(privateKey);
        return crypto2.adoptLocalSecret(BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), basicAgreement.calculateAgreement(publicKey)));
    }

    public static ECDomainParameters getDomainParameters(TlsECConfig ecConfig) {
        return getDomainParameters(ecConfig.getNamedGroup());
    }

    public static ECDomainParameters getDomainParameters(int namedGroup) {
        if (!NamedGroup.refersToASpecificCurve(namedGroup)) {
            return null;
        }
        String curveName = NamedGroup.getCurveName(namedGroup);
        X9ECParameters ecP = CustomNamedCurves.getByName(curveName);
        if (ecP == null && (ecP = ECNamedCurveTable.getByName(curveName)) == null) {
            return null;
        }
        return new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }

    public BcTlsECDomain(BcTlsCrypto crypto2, TlsECConfig ecConfig) {
        this.crypto = crypto2;
        this.config = ecConfig;
        this.domainParameters = getDomainParameters(ecConfig);
    }

    public BcTlsSecret calculateECDHAgreement(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey) {
        return calculateECDHAgreement(this.crypto, privateKey, publicKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new BcTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] encoding) {
        return this.domainParameters.getCurve().decodePoint(encoding);
    }

    public ECPublicKeyParameters decodePublicKey(byte[] encoding) throws IOException {
        try {
            return new ECPublicKeyParameters(decodePoint(encoding), this.domainParameters);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    public byte[] encodePoint(ECPoint point) {
        return point.getEncoded(false);
    }

    public byte[] encodePublicKey(ECPublicKeyParameters publicKey) {
        return encodePoint(publicKey.getQ());
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(this.domainParameters, this.crypto.getSecureRandom()));
        return keyPairGenerator.generateKeyPair();
    }
}
