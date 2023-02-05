package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECNamedDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import java.io.IOException;

public class OpenSSHPublicKeyUtil {
    private static final String DSS = "ssh-dss";
    private static final String ECDSA = "ecdsa";
    private static final String ED_25519 = "ssh-ed25519";
    private static final String RSA = "ssh-rsa";

    private OpenSSHPublicKeyUtil() {
    }

    public static AsymmetricKeyParameter parsePublicKey(byte[] encoded) {
        return parsePublicKey(new SSHBuffer(encoded));
    }

    public static byte[] encodePublicKey(AsymmetricKeyParameter cipherParameters) throws IOException {
        if (cipherParameters == null) {
            throw new IllegalArgumentException("cipherParameters was null.");
        } else if (cipherParameters instanceof RSAKeyParameters) {
            if (cipherParameters.isPrivate()) {
                throw new IllegalArgumentException("RSAKeyParamaters was for encryption");
            }
            RSAKeyParameters rsaPubKey = (RSAKeyParameters) cipherParameters;
            SSHBuilder builder = new SSHBuilder();
            builder.writeString(RSA);
            builder.writeBigNum(rsaPubKey.getExponent());
            builder.writeBigNum(rsaPubKey.getModulus());
            return builder.getBytes();
        } else if (cipherParameters instanceof ECPublicKeyParameters) {
            SSHBuilder builder2 = new SSHBuilder();
            String name = SSHNamedCurves.getNameForParameters(((ECPublicKeyParameters) cipherParameters).getParameters());
            if (name == null) {
                throw new IllegalArgumentException("unable to derive ssh curve name for " + ((ECPublicKeyParameters) cipherParameters).getParameters().getCurve().getClass().getName());
            }
            builder2.writeString("ecdsa-sha2-" + name);
            builder2.writeString(name);
            builder2.writeBlock(((ECPublicKeyParameters) cipherParameters).getQ().getEncoded(false));
            return builder2.getBytes();
        } else if (cipherParameters instanceof DSAPublicKeyParameters) {
            DSAPublicKeyParameters dsaPubKey = (DSAPublicKeyParameters) cipherParameters;
            DSAParameters dsaParams = dsaPubKey.getParameters();
            SSHBuilder builder3 = new SSHBuilder();
            builder3.writeString(DSS);
            builder3.writeBigNum(dsaParams.getP());
            builder3.writeBigNum(dsaParams.getQ());
            builder3.writeBigNum(dsaParams.getG());
            builder3.writeBigNum(dsaPubKey.getY());
            return builder3.getBytes();
        } else if (cipherParameters instanceof Ed25519PublicKeyParameters) {
            SSHBuilder builder4 = new SSHBuilder();
            builder4.writeString(ED_25519);
            builder4.writeBlock(((Ed25519PublicKeyParameters) cipherParameters).getEncoded());
            return builder4.getBytes();
        } else {
            throw new IllegalArgumentException("unable to convert " + cipherParameters.getClass().getName() + " to private key");
        }
    }

    public static AsymmetricKeyParameter parsePublicKey(SSHBuffer buffer) {
        AsymmetricKeyParameter result = null;
        String magic = buffer.readString();
        if (RSA.equals(magic)) {
            result = new RSAKeyParameters(false, buffer.readBigNumPositive(), buffer.readBigNumPositive());
        } else if (DSS.equals(magic)) {
            result = new DSAPublicKeyParameters(buffer.readBigNumPositive(), new DSAParameters(buffer.readBigNumPositive(), buffer.readBigNumPositive(), buffer.readBigNumPositive()));
        } else if (magic.startsWith(ECDSA)) {
            String curveName = buffer.readString();
            ASN1ObjectIdentifier oid = SSHNamedCurves.getByName(curveName);
            X9ECParameters x9ECParameters = SSHNamedCurves.getParameters(oid);
            if (x9ECParameters == null) {
                throw new IllegalStateException("unable to find curve for " + magic + " using curve name " + curveName);
            }
            result = new ECPublicKeyParameters(x9ECParameters.getCurve().decodePoint(buffer.readBlock()), new ECNamedDomainParameters(oid, x9ECParameters));
        } else if (ED_25519.equals(magic)) {
            byte[] pubKeyBytes = buffer.readBlock();
            if (pubKeyBytes.length != 32) {
                throw new IllegalStateException("public key value of wrong length");
            }
            result = new Ed25519PublicKeyParameters(pubKeyBytes, 0);
        }
        if (result == null) {
            throw new IllegalArgumentException("unable to parse key");
        } else if (!buffer.hasRemaining()) {
            return result;
        } else {
            throw new IllegalArgumentException("decoded key has trailing data");
        }
    }
}
