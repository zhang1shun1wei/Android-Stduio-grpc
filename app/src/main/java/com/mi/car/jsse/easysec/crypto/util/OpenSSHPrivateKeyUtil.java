package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.nist.NISTNamedCurves;
import com.mi.car.jsse.easysec.asn1.pkcs.RSAPrivateKey;
import com.mi.car.jsse.easysec.asn1.sec.ECPrivateKey;
import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECNamedDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAPrivateCrtKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.math.BigInteger;

public class OpenSSHPrivateKeyUtil {
    static final byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1\u0000");

    private OpenSSHPrivateKeyUtil() {
    }

    public static byte[] encodePrivateKey(AsymmetricKeyParameter params) throws IOException {
        if (params == null) {
            throw new IllegalArgumentException("param is null");
        } else if (params instanceof RSAPrivateCrtKeyParameters) {
            return PrivateKeyInfoFactory.createPrivateKeyInfo(params).parsePrivateKey().toASN1Primitive().getEncoded();
        } else {
            if (params instanceof ECPrivateKeyParameters) {
                return PrivateKeyInfoFactory.createPrivateKeyInfo(params).parsePrivateKey().toASN1Primitive().getEncoded();
            }
            if (params instanceof DSAPrivateKeyParameters) {
                DSAPrivateKeyParameters dsaPrivKey = (DSAPrivateKeyParameters) params;
                DSAParameters dsaParams = dsaPrivKey.getParameters();
                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new ASN1Integer(0));
                vec.add(new ASN1Integer(dsaParams.getP()));
                vec.add(new ASN1Integer(dsaParams.getQ()));
                vec.add(new ASN1Integer(dsaParams.getG()));
                vec.add(new ASN1Integer(dsaParams.getG().modPow(dsaPrivKey.getX(), dsaParams.getP())));
                vec.add(new ASN1Integer(dsaPrivKey.getX()));
                try {
                    return new DERSequence(vec).getEncoded();
                } catch (Exception ex) {
                    throw new IllegalStateException("unable to encode DSAPrivateKeyParameters " + ex.getMessage());
                }
            } else if (params instanceof Ed25519PrivateKeyParameters) {
                Ed25519PublicKeyParameters publicKeyParameters = ((Ed25519PrivateKeyParameters) params).generatePublicKey();
                SSHBuilder builder = new SSHBuilder();
                builder.writeBytes(AUTH_MAGIC);
                builder.writeString("none");
                builder.writeString("none");
                builder.writeString("");
                builder.u32(1);
                builder.writeBlock(OpenSSHPublicKeyUtil.encodePublicKey(publicKeyParameters));
                SSHBuilder pkBuild = new SSHBuilder();
                int checkint = CryptoServicesRegistrar.getSecureRandom().nextInt();
                pkBuild.u32(checkint);
                pkBuild.u32(checkint);
                pkBuild.writeString("ssh-ed25519");
                byte[] pubKeyEncoded = publicKeyParameters.getEncoded();
                pkBuild.writeBlock(pubKeyEncoded);
                pkBuild.writeBlock(Arrays.concatenate(((Ed25519PrivateKeyParameters) params).getEncoded(), pubKeyEncoded));
                pkBuild.writeString("");
                builder.writeBlock(pkBuild.getPaddedBytes());
                return builder.getBytes();
            } else {
                throw new IllegalArgumentException("unable to convert " + params.getClass().getName() + " to openssh private key");
            }
        }
    }

    public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] blob) {
        AsymmetricKeyParameter result = null;
        if (blob[0] == 48) {
            ASN1Sequence sequence = ASN1Sequence.getInstance(blob);
            if (sequence.size() == 6) {
                if (allIntegers(sequence) && ((ASN1Integer) sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO)) {
                    result = new DSAPrivateKeyParameters(((ASN1Integer) sequence.getObjectAt(5)).getPositiveValue(), new DSAParameters(((ASN1Integer) sequence.getObjectAt(1)).getPositiveValue(), ((ASN1Integer) sequence.getObjectAt(2)).getPositiveValue(), ((ASN1Integer) sequence.getObjectAt(3)).getPositiveValue()));
                }
            } else if (sequence.size() == 9) {
                if (allIntegers(sequence) && ((ASN1Integer) sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO)) {
                    RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(sequence);
                    result = new RSAPrivateCrtKeyParameters(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent(), rsaPrivateKey.getPrivateExponent(), rsaPrivateKey.getPrime1(), rsaPrivateKey.getPrime2(), rsaPrivateKey.getExponent1(), rsaPrivateKey.getExponent2(), rsaPrivateKey.getCoefficient());
                }
            } else if (sequence.size() == 4 && (sequence.getObjectAt(3) instanceof ASN1TaggedObject) && (sequence.getObjectAt(2) instanceof ASN1TaggedObject)) {
                ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(sequence);
                ASN1ObjectIdentifier curveOID = ASN1ObjectIdentifier.getInstance(ecPrivateKey.getParametersObject());
                result = new ECPrivateKeyParameters(ecPrivateKey.getKey(), new ECNamedDomainParameters(curveOID, ECNamedCurveTable.getByOID(curveOID)));
            }
        } else {
            SSHBuffer kIn = new SSHBuffer(AUTH_MAGIC, blob);
            if (!"none".equals(kIn.readString())) {
                throw new IllegalStateException("encrypted keys not supported");
            }
            kIn.skipBlock();
            kIn.skipBlock();
            if (kIn.readU32() != 1) {
                throw new IllegalStateException("multiple keys not supported");
            }
            OpenSSHPublicKeyUtil.parsePublicKey(kIn.readBlock());
            byte[] privateKeyBlock = kIn.readPaddedBlock();
            if (kIn.hasRemaining()) {
                throw new IllegalArgumentException("decoded key has trailing data");
            }
            SSHBuffer pkIn = new SSHBuffer(privateKeyBlock);
            if (pkIn.readU32() != pkIn.readU32()) {
                throw new IllegalStateException("private key check values are not the same");
            }
            String keyType = pkIn.readString();
            if ("ssh-ed25519".equals(keyType)) {
                pkIn.readBlock();
                byte[] edPrivateKey = pkIn.readBlock();
                if (edPrivateKey.length != 64) {
                    throw new IllegalStateException("private key value of wrong length");
                }
                result = new Ed25519PrivateKeyParameters(edPrivateKey, 0);
            } else if (keyType.startsWith("ecdsa")) {
                ASN1ObjectIdentifier oid = SSHNamedCurves.getByName(Strings.fromByteArray(pkIn.readBlock()));
                if (oid == null) {
                    throw new IllegalStateException("OID not found for: " + keyType);
                }
                X9ECParameters curveParams = NISTNamedCurves.getByOID(oid);
                if (curveParams == null) {
                    throw new IllegalStateException("Curve not found for: " + oid);
                }
                pkIn.readBlock();
                result = new ECPrivateKeyParameters(new BigInteger(1, pkIn.readBlock()), new ECNamedDomainParameters(oid, curveParams));
            } else if (keyType.startsWith("ssh-rsa")) {
                BigInteger modulus = new BigInteger(1, pkIn.readBlock());
                BigInteger pubExp = new BigInteger(1, pkIn.readBlock());
                BigInteger privExp = new BigInteger(1, pkIn.readBlock());
                BigInteger coef = new BigInteger(1, pkIn.readBlock());
                BigInteger p = new BigInteger(1, pkIn.readBlock());
                BigInteger q = new BigInteger(1, pkIn.readBlock());
                result = new RSAPrivateCrtKeyParameters(modulus, pubExp, privExp, p, q, privExp.remainder(p.subtract(BigIntegers.ONE)), privExp.remainder(q.subtract(BigIntegers.ONE)), coef);
            }
            pkIn.skipBlock();
            if (pkIn.hasRemaining()) {
                throw new IllegalArgumentException("private key block has trailing data");
            }
        }
        if (result != null) {
            return result;
        }
        throw new IllegalArgumentException("unable to parse key");
    }

    private static boolean allIntegers(ASN1Sequence sequence) {
        for (int t = 0; t < sequence.size(); t++) {
            if (!(sequence.getObjectAt(t) instanceof ASN1Integer)) {
                return false;
            }
        }
        return true;
    }
}
