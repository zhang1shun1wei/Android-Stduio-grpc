package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.sec.ECPrivateKeyStructure;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.EC5Util;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.ECUtil;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.mi.car.jsse.easysec.jce.interfaces.ECPointEncoder;
import com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier;
import com.mi.car.jsse.easysec.jce.spec.ECNamedCurveSpec;
import com.mi.car.jsse.easysec.jce.spec.ECPrivateKeySpec;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Enumeration;

public class JCEECPrivateKey implements ECPrivateKey, com.mi.car.jsse.easysec.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder {
    private String algorithm = "EC";
    private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
    private BigInteger d;
    private ECParameterSpec ecSpec;
    private ASN1BitString publicKey;
    private boolean withCompression;

    protected JCEECPrivateKey() {
    }

    public JCEECPrivateKey(ECPrivateKey key) {
        this.d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
    }

    public JCEECPrivateKey(String algorithm2, ECPrivateKeySpec spec) {
        this.algorithm = algorithm2;
        this.d = spec.getD();
        if (spec.getParams() != null) {
            this.ecSpec = EC5Util.convertSpec(EC5Util.convertCurve(spec.getParams().getCurve(), spec.getParams().getSeed()), spec.getParams());
        } else {
            this.ecSpec = null;
        }
    }

    public JCEECPrivateKey(String algorithm2, java.security.spec.ECPrivateKeySpec spec) {
        this.algorithm = algorithm2;
        this.d = spec.getS();
        this.ecSpec = spec.getParams();
    }

    public JCEECPrivateKey(String algorithm2, JCEECPrivateKey key) {
        this.algorithm = algorithm2;
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.attrCarrier = key.attrCarrier;
        this.publicKey = key.publicKey;
    }

    public JCEECPrivateKey(String algorithm2, ECPrivateKeyParameters params, JCEECPublicKey pubKey, ECParameterSpec spec) {
        this.algorithm = algorithm2;
        this.d = params.getD();
        if (spec == null) {
            ECDomainParameters dp = params.getParameters();
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
        } else {
            this.ecSpec = spec;
        }
        this.publicKey = getPublicKeyDetails(pubKey);
    }

    public JCEECPrivateKey(String algorithm2, ECPrivateKeyParameters params, JCEECPublicKey pubKey, com.mi.car.jsse.easysec.jce.spec.ECParameterSpec spec) {
        this.algorithm = algorithm2;
        this.d = params.getD();
        if (spec == null) {
            ECDomainParameters dp = params.getParameters();
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
        } else {
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(spec.getCurve(), spec.getSeed()), EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
        }
        this.publicKey = getPublicKeyDetails(pubKey);
    }

    public JCEECPrivateKey(String algorithm2, ECPrivateKeyParameters params) {
        this.algorithm = algorithm2;
        this.d = params.getD();
        this.ecSpec = null;
    }

    JCEECPrivateKey(PrivateKeyInfo info) throws IOException {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info) throws IOException {
        X962Parameters params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        if (params.isNamedCurve()) {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);
            if (ecP != null) {
                this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed()), EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
            }
        } else if (params.isImplicitlyCA()) {
            this.ecSpec = null;
        } else {
            X9ECParameters ecP2 = X9ECParameters.getInstance(params.getParameters());
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(ecP2.getCurve(), ecP2.getSeed()), EC5Util.convertPoint(ecP2.getG()), ecP2.getN(), ecP2.getH().intValue());
        }
        ASN1Encodable privKey = info.parsePrivateKey();
        if (privKey instanceof ASN1Integer) {
            this.d = ASN1Integer.getInstance(privKey).getValue();
            return;
        }
        ECPrivateKeyStructure ec = new ECPrivateKeyStructure((ASN1Sequence) privKey);
        this.d = ec.getKey();
        this.publicKey = ec.getPublicKey();
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        X962Parameters params;
        ECPrivateKeyStructure keyStructure;
        PrivateKeyInfo info;
        if (this.ecSpec instanceof ECNamedCurveSpec) {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec) this.ecSpec).getName());
            if (curveOid == null) {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec) this.ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        } else if (this.ecSpec == null) {
            params = new X962Parameters((ASN1Null) DERNull.INSTANCE);
        } else {
            ECCurve curve = EC5Util.convertCurve(this.ecSpec.getCurve());
            params = new X962Parameters(new X9ECParameters(curve, new X9ECPoint(EC5Util.convertPoint(curve, this.ecSpec.getGenerator()), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long) this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed()));
        }
        if (this.publicKey != null) {
            keyStructure = new ECPrivateKeyStructure(getS(), this.publicKey, params);
        } else {
            keyStructure = new ECPrivateKeyStructure(getS(), params);
        }
        try {
            if (this.algorithm.equals("ECGOST3410")) {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.toASN1Primitive()), keyStructure.toASN1Primitive());
            } else {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive()), keyStructure.toASN1Primitive());
            }
            return info.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
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

    /* access modifiers changed from: package-private */
    public com.mi.car.jsse.easysec.jce.spec.ECParameterSpec engineGetSpec() {
        if (this.ecSpec != null) {
            return EC5Util.convertSpec(this.ecSpec);
        }
        return EasysecProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public BigInteger getS() {
        return this.d;
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ECPrivateKey
    public BigInteger getD() {
        return this.d;
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier
    public void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute) {
        this.attrCarrier.setBagAttribute(oid, attribute);
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier
    public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid) {
        return this.attrCarrier.getBagAttribute(oid);
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier
    public Enumeration getBagAttributeKeys() {
        return this.attrCarrier.getBagAttributeKeys();
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ECPointEncoder
    public void setPointFormat(String style) {
        this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(style);
    }

    public boolean equals(Object o) {
        if (!(o instanceof JCEECPrivateKey)) {
            return false;
        }
        JCEECPrivateKey other = (JCEECPrivateKey) o;
        if (!getD().equals(other.getD()) || !engineGetSpec().equals(other.engineGetSpec())) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();
        buf.append("EC Private Key").append(nl);
        buf.append("             S: ").append(this.d.toString(16)).append(nl);
        return buf.toString();
    }

    private ASN1BitString getPublicKeyDetails(JCEECPublicKey pub) {
        try {
            return SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded())).getPublicKeyData();
        } catch (IOException e) {
            return null;
        }
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray((byte[]) in.readObject())));
        this.algorithm = (String) in.readObject();
        this.withCompression = in.readBoolean();
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
        this.attrCarrier.readObject(in);
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getEncoded());
        out.writeObject(this.algorithm);
        out.writeBoolean(this.withCompression);
        this.attrCarrier.writeObject(out);
    }
}
