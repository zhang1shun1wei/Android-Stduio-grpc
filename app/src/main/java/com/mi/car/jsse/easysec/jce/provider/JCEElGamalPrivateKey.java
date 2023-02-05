package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.oiw.ElGamalParameter;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPrivateKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.KeyUtil;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.mi.car.jsse.easysec.jce.interfaces.ElGamalPrivateKey;
import com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier;
import com.mi.car.jsse.easysec.jce.spec.ElGamalParameterSpec;
import com.mi.car.jsse.easysec.jce.spec.ElGamalPrivateKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

public class JCEElGamalPrivateKey implements ElGamalPrivateKey, DHPrivateKey, PKCS12BagAttributeCarrier {
    static final long serialVersionUID = 4819350091141529678L;
    private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
    ElGamalParameterSpec elSpec;
    BigInteger x;

    protected JCEElGamalPrivateKey() {
    }

    JCEElGamalPrivateKey(ElGamalPrivateKey key) {
        this.x = key.getX();
        this.elSpec = key.getParameters();
    }

    JCEElGamalPrivateKey(DHPrivateKey key) {
        this.x = key.getX();
        this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
    }

    JCEElGamalPrivateKey(ElGamalPrivateKeySpec spec) {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    JCEElGamalPrivateKey(DHPrivateKeySpec spec) {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
    }

    JCEElGamalPrivateKey(PrivateKeyInfo info) throws IOException {
        ElGamalParameter params = ElGamalParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        this.x = ASN1Integer.getInstance(info.parsePrivateKey()).getValue();
        this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
    }

    JCEElGamalPrivateKey(ElGamalPrivateKeyParameters params) {
        this.x = params.getX();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    public String getAlgorithm() {
        return "ElGamal";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(this.elSpec.getP(), this.elSpec.getG())), new ASN1Integer(getX()));
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ElGamalKey
    public ElGamalParameterSpec getParameters() {
        return this.elSpec;
    }

    public DHParameterSpec getParams() {
        return new DHParameterSpec(this.elSpec.getP(), this.elSpec.getG());
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ElGamalPrivateKey
    public BigInteger getX() {
        return this.x;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.x = (BigInteger) in.readObject();
        this.elSpec = new ElGamalParameterSpec((BigInteger) in.readObject(), (BigInteger) in.readObject());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getX());
        out.writeObject(this.elSpec.getP());
        out.writeObject(this.elSpec.getG());
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
