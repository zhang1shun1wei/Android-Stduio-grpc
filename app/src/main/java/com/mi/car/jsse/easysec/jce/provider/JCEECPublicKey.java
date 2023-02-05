package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cryptopro.ECGOST3410NamedCurves;
import com.mi.car.jsse.easysec.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.asn1.x9.X9IntegerConverter;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.EC5Util;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.ECUtil;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.KeyUtil;
import com.mi.car.jsse.easysec.jce.ECGOST3410NamedCurveTable;
import com.mi.car.jsse.easysec.jce.interfaces.ECPointEncoder;
import com.mi.car.jsse.easysec.jce.spec.ECNamedCurveParameterSpec;
import com.mi.car.jsse.easysec.jce.spec.ECNamedCurveSpec;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

public class JCEECPublicKey implements ECPublicKey, com.mi.car.jsse.easysec.jce.interfaces.ECPublicKey, ECPointEncoder {
    private String algorithm = "EC";
    private ECParameterSpec ecSpec;
    private GOST3410PublicKeyAlgParameters gostParams;
    private ECPoint q;
    private boolean withCompression;

    public JCEECPublicKey(String algorithm2, JCEECPublicKey key) {
        this.algorithm = algorithm2;
        this.q = key.q;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.gostParams = key.gostParams;
    }

    public JCEECPublicKey(String algorithm2, ECPublicKeySpec spec) {
        this.algorithm = algorithm2;
        this.ecSpec = spec.getParams();
        this.q = EC5Util.convertPoint(this.ecSpec, spec.getW());
    }

    public JCEECPublicKey(String algorithm2, com.mi.car.jsse.easysec.jce.spec.ECPublicKeySpec spec) {
        this.algorithm = algorithm2;
        this.q = spec.getQ();
        if (spec.getParams() != null) {
            this.ecSpec = EC5Util.convertSpec(EC5Util.convertCurve(spec.getParams().getCurve(), spec.getParams().getSeed()), spec.getParams());
            return;
        }
        if (this.q.getCurve() == null) {
            this.q = EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getCurve().createPoint(this.q.getAffineXCoord().toBigInteger(), this.q.getAffineYCoord().toBigInteger());
        }
        this.ecSpec = null;
    }

    public JCEECPublicKey(String algorithm2, ECPublicKeyParameters params, ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();
        this.algorithm = algorithm2;
        this.q = params.getQ();
        if (spec == null) {
            this.ecSpec = createSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), dp);
        } else {
            this.ecSpec = spec;
        }
    }

    public JCEECPublicKey(String algorithm2, ECPublicKeyParameters params, com.mi.car.jsse.easysec.jce.spec.ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();
        this.algorithm = algorithm2;
        this.q = params.getQ();
        if (spec == null) {
            this.ecSpec = createSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), dp);
        } else {
            this.ecSpec = EC5Util.convertSpec(EC5Util.convertCurve(spec.getCurve(), spec.getSeed()), spec);
        }
    }

    public JCEECPublicKey(String algorithm2, ECPublicKeyParameters params) {
        this.algorithm = algorithm2;
        this.q = params.getQ();
        this.ecSpec = null;
    }

    private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp) {
        return new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
    }

    public JCEECPublicKey(ECPublicKey key) {
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.q = EC5Util.convertPoint(this.ecSpec, key.getW());
    }

    JCEECPublicKey(SubjectPublicKeyInfo info) {
        populateFromPubKeyInfo(info);
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info) {
        ECCurve curve;
        AlgorithmIdentifier algID = info.getAlgorithm();
        if (algID.getAlgorithm().equals((ASN1Primitive) CryptoProObjectIdentifiers.gostR3410_2001)) {
            ASN1BitString bits = info.getPublicKeyData();
            this.algorithm = "ECGOST3410";
            try {
                byte[] keyEnc = ((ASN1OctetString) ASN1Primitive.fromByteArray(bits.getBytes())).getOctets();
                byte[] x9Encoding = new byte[65];
                x9Encoding[0] = 4;
                for (int i = 1; i <= 32; i++) {
                    x9Encoding[i] = keyEnc[32 - i];
                    x9Encoding[i + 32] = keyEnc[64 - i];
                }
                this.gostParams = GOST3410PublicKeyAlgParameters.getInstance(algID.getParameters());
                ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(this.gostParams.getPublicKeyParamSet()));
                ECCurve curve2 = spec.getCurve();
                EllipticCurve ellipticCurve = EC5Util.convertCurve(curve2, spec.getSeed());
                this.q = curve2.decodePoint(x9Encoding);
                this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(this.gostParams.getPublicKeyParamSet()), ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH());
            } catch (IOException e) {
                throw new IllegalArgumentException("error recovering public key");
            }
        } else {
            X962Parameters params = X962Parameters.getInstance(algID.getParameters());
            if (params.isNamedCurve()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) params.getParameters();
                X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);
                curve = ecP.getCurve();
                this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), EC5Util.convertCurve(curve, ecP.getSeed()), EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
            } else if (params.isImplicitlyCA()) {
                this.ecSpec = null;
                curve = EasysecProvider.CONFIGURATION.getEcImplicitlyCa().getCurve();
            } else {
                X9ECParameters ecP2 = X9ECParameters.getInstance(params.getParameters());
                curve = ecP2.getCurve();
                this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(curve, ecP2.getSeed()), EC5Util.convertPoint(ecP2.getG()), ecP2.getN(), ecP2.getH().intValue());
            }
            byte[] data = info.getPublicKeyData().getBytes();
            ASN1OctetString key = new DEROctetString(data);
            if (data[0] == 4 && data[1] == data.length - 2 && ((data[2] == 2 || data[2] == 3) && new X9IntegerConverter().getByteLength(curve) >= data.length - 3)) {
                try {
                    key = (ASN1OctetString) ASN1Primitive.fromByteArray(data);
                } catch (IOException e2) {
                    throw new IllegalArgumentException("error recovering public key");
                }
            }
            this.q = new X9ECPoint(curve, key).getPoint();
        }
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        ASN1Encodable params;
        SubjectPublicKeyInfo info;
        ASN1Encodable params2;
        if (this.algorithm.equals("ECGOST3410")) {
            if (this.gostParams != null) {
                params2 = this.gostParams;
            } else if (this.ecSpec instanceof ECNamedCurveSpec) {
                params2 = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec) this.ecSpec).getName()), CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
            } else {
                ECCurve curve = EC5Util.convertCurve(this.ecSpec.getCurve());
                params2 = new X962Parameters(new X9ECParameters(curve, new X9ECPoint(EC5Util.convertPoint(curve, this.ecSpec.getGenerator()), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long) this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed()));
            }
            BigInteger bX = this.q.getAffineXCoord().toBigInteger();
            BigInteger bY = this.q.getAffineYCoord().toBigInteger();
            byte[] encKey = new byte[64];
            extractBytes(encKey, 0, bX);
            extractBytes(encKey, 32, bY);
            try {
                info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params2), new DEROctetString(encKey));
            } catch (IOException e) {
                return null;
            }
        } else {
            if (this.ecSpec instanceof ECNamedCurveSpec) {
                ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec) this.ecSpec).getName());
                if (curveOid == null) {
                    curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec) this.ecSpec).getName());
                }
                params = new X962Parameters(curveOid);
            } else if (this.ecSpec == null) {
                params = new X962Parameters((ASN1Null) DERNull.INSTANCE);
            } else {
                ECCurve curve2 = EC5Util.convertCurve(this.ecSpec.getCurve());
                params = new X962Parameters(new X9ECParameters(curve2, new X9ECPoint(EC5Util.convertPoint(curve2, this.ecSpec.getGenerator()), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long) this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed()));
            }
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), getQ().getEncoded(this.withCompression));
        }
        return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI) {
        byte[] val = bI.toByteArray();
        if (val.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }
        for (int i = 0; i != 32; i++) {
            encKey[offSet + i] = val[(val.length - 1) - i];
        }
    }

    public ECParameterSpec getParams() {
        return this.ecSpec;
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ECKey
    public com.mi.car.jsse.easysec.jce.spec.ECParameterSpec getParameters() {
        if (this.ecSpec == null) {
            return null;
        }
        return EC5Util.convertSpec(this.ecSpec);
    }

    public java.security.spec.ECPoint getW() {
        return EC5Util.convertPoint(this.q);
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ECPublicKey
    public ECPoint getQ() {
        if (this.ecSpec == null) {
            return this.q.getDetachedPoint();
        }
        return this.q;
    }

    public ECPoint engineGetQ() {
        return this.q;
    }

    /* access modifiers changed from: package-private */
    public com.mi.car.jsse.easysec.jce.spec.ECParameterSpec engineGetSpec() {
        if (this.ecSpec != null) {
            return EC5Util.convertSpec(this.ecSpec);
        }
        return EasysecProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();
        buf.append("EC Public Key").append(nl);
        buf.append("            X: ").append(this.q.getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(this.q.getAffineYCoord().toBigInteger().toString(16)).append(nl);
        return buf.toString();
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ECPointEncoder
    public void setPointFormat(String style) {
        this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(style);
    }

    public boolean equals(Object o) {
        if (!(o instanceof JCEECPublicKey)) {
            return false;
        }
        JCEECPublicKey other = (JCEECPublicKey) o;
        if (!engineGetQ().equals(other.engineGetQ()) || !engineGetSpec().equals(other.engineGetSpec())) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return engineGetQ().hashCode() ^ engineGetSpec().hashCode();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray((byte[]) in.readObject())));
        this.algorithm = (String) in.readObject();
        this.withCompression = in.readBoolean();
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getEncoded());
        out.writeObject(this.algorithm);
        out.writeBoolean(this.withCompression);
    }
}
