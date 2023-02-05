package com.mi.car.jsse.easysec.jce;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.ECUtil;
import com.mi.car.jsse.easysec.jce.provider.EasysecProvider;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECKeyUtil {
    public static PublicKey publicToExplicitParameters(PublicKey key, String providerName) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException {
        Provider provider = Security.getProvider(providerName);
        if (provider != null) {
            return publicToExplicitParameters(key, provider);
        }
        throw new NoSuchProviderException("cannot find provider: " + providerName);
    }

    public static PublicKey publicToExplicitParameters(PublicKey key, Provider provider) throws IllegalArgumentException, NoSuchAlgorithmException {
        X9ECParameters curveParams;
        try {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(key.getEncoded()));
            if (info.getAlgorithm().getAlgorithm().equals((ASN1Primitive) CryptoProObjectIdentifiers.gostR3410_2001)) {
                throw new IllegalArgumentException("cannot convert GOST key to explicit parameters.");
            }
            X962Parameters params = X962Parameters.getInstance(info.getAlgorithm().getParameters());
            if (params.isNamedCurve()) {
                curveParams = ECUtil.getNamedCurveByOid(ASN1ObjectIdentifier.getInstance(params.getParameters()));
                if (curveParams.hasSeed()) {
                    curveParams = new X9ECParameters(curveParams.getCurve(), curveParams.getBaseEntry(), curveParams.getN(), curveParams.getH());
                }
            } else if (!params.isImplicitlyCA()) {
                return key;
            } else {
                curveParams = new X9ECParameters(EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getCurve(), new X9ECPoint(EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getG(), false), EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getN(), EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getH());
            }
            return KeyFactory.getInstance(key.getAlgorithm(), provider).generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(curveParams)), info.getPublicKeyData().getBytes()).getEncoded()));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (NoSuchAlgorithmException e2) {
            throw e2;
        } catch (Exception e3) {
            throw new UnexpectedException(e3);
        }
    }

    public static PrivateKey privateToExplicitParameters(PrivateKey key, String providerName) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException {
        Provider provider = Security.getProvider(providerName);
        if (provider != null) {
            return privateToExplicitParameters(key, provider);
        }
        throw new NoSuchProviderException("cannot find provider: " + providerName);
    }

    public static PrivateKey privateToExplicitParameters(PrivateKey key, Provider provider) throws IllegalArgumentException, NoSuchAlgorithmException {
        X9ECParameters curveParams;
        try {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(key.getEncoded()));
            if (info.getPrivateKeyAlgorithm().getAlgorithm().equals((ASN1Primitive) CryptoProObjectIdentifiers.gostR3410_2001)) {
                throw new UnsupportedEncodingException("cannot convert GOST key to explicit parameters.");
            }
            X962Parameters params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());
            if (params.isNamedCurve()) {
                curveParams = ECUtil.getNamedCurveByOid(ASN1ObjectIdentifier.getInstance(params.getParameters()));
                if (curveParams.hasSeed()) {
                    curveParams = new X9ECParameters(curveParams.getCurve(), curveParams.getBaseEntry(), curveParams.getN(), curveParams.getH());
                }
            } else if (!params.isImplicitlyCA()) {
                return key;
            } else {
                curveParams = new X9ECParameters(EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getCurve(), new X9ECPoint(EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getG(), false), EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getN(), EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getH());
            }
            return KeyFactory.getInstance(key.getAlgorithm(), provider).generatePrivate(new PKCS8EncodedKeySpec(new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(curveParams)), info.parsePrivateKey()).getEncoded()));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (NoSuchAlgorithmException e2) {
            throw e2;
        } catch (Exception e3) {
            throw new UnexpectedException(e3);
        }
    }

    /* access modifiers changed from: private */
    public static class UnexpectedException extends RuntimeException {
        private Throwable cause;

        UnexpectedException(Throwable cause2) {
            super(cause2.toString());
            this.cause = cause2;
        }

        public Throwable getCause() {
            return this.cause;
        }
    }
}
