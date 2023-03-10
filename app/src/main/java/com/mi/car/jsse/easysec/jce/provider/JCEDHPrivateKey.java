package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.pkcs.DHParameter;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x9.DHDomainParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

public class JCEDHPrivateKey implements DHPrivateKey, PKCS12BagAttributeCarrier {
    static final long serialVersionUID = 311058815616901812L;
    private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();
    private DHParameterSpec dhSpec;
    private PrivateKeyInfo info;
    BigInteger x;

    protected JCEDHPrivateKey() {
    }

    JCEDHPrivateKey(DHPrivateKey key) {
        this.x = key.getX();
        this.dhSpec = key.getParams();
    }

    JCEDHPrivateKey(DHPrivateKeySpec spec) {
        this.x = spec.getX();
        this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
    }

    JCEDHPrivateKey(PrivateKeyInfo info2) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(info2.getPrivateKeyAlgorithm().getParameters());
        ASN1Integer derX = ASN1Integer.getInstance(info2.parsePrivateKey());
        ASN1ObjectIdentifier id = info2.getPrivateKeyAlgorithm().getAlgorithm();
        this.info = info2;
        this.x = derX.getValue();
        if (id.equals((ASN1Primitive) PKCSObjectIdentifiers.dhKeyAgreement)) {
            DHParameter params = DHParameter.getInstance(seq);
            if (params.getL() != null) {
                this.dhSpec = new DHParameterSpec(params.getP(), params.getG(), params.getL().intValue());
            } else {
                this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
            }
        } else if (id.equals((ASN1Primitive) X9ObjectIdentifiers.dhpublicnumber)) {
            DHDomainParameters params2 = DHDomainParameters.getInstance(seq);
            this.dhSpec = new DHParameterSpec(params2.getP().getValue(), params2.getG().getValue());
        } else {
            throw new IllegalArgumentException("unknown algorithm type: " + id);
        }
    }

    JCEDHPrivateKey(DHPrivateKeyParameters params) {
        this.x = params.getX();
        this.dhSpec = new DHParameterSpec(params.getParameters().getP(), params.getParameters().getG(), params.getParameters().getL());
    }

    public String getAlgorithm() {
        return "DH";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        try {
            if (this.info != null) {
                return this.info.getEncoded(ASN1Encoding.DER);
            }
            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(this.dhSpec.getP(), this.dhSpec.getG(), this.dhSpec.getL())), new ASN1Integer(getX())).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    public DHParameterSpec getParams() {
        return this.dhSpec;
    }

    public BigInteger getX() {
        return this.x;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.x = (BigInteger) in.readObject();
        this.dhSpec = new DHParameterSpec((BigInteger) in.readObject(), (BigInteger) in.readObject(), in.readInt());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getX());
        out.writeObject(this.dhSpec.getP());
        out.writeObject(this.dhSpec.getG());
        out.writeInt(this.dhSpec.getL());
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
}
