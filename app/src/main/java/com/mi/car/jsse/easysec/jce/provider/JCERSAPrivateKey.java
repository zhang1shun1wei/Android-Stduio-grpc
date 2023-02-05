package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.KeyUtil;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.mi.car.jsse.easysec.jce.interfaces.PKCS12BagAttributeCarrier;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;

public class JCERSAPrivateKey implements RSAPrivateKey, PKCS12BagAttributeCarrier {
    private static BigInteger ZERO = BigInteger.valueOf(0);
    static final long serialVersionUID = 5110188922551353628L;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
    protected BigInteger modulus;
    protected BigInteger privateExponent;

    protected JCERSAPrivateKey() {
    }

    JCERSAPrivateKey(RSAKeyParameters key) {
        this.modulus = key.getModulus();
        this.privateExponent = key.getExponent();
    }

    JCERSAPrivateKey(RSAPrivateKeySpec spec) {
        this.modulus = spec.getModulus();
        this.privateExponent = spec.getPrivateExponent();
    }

    JCERSAPrivateKey(RSAPrivateKey key) {
        this.modulus = key.getModulus();
        this.privateExponent = key.getPrivateExponent();
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public BigInteger getPrivateExponent() {
        return this.privateExponent;
    }

    public String getAlgorithm() {
        return "RSA";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new com.mi.car.jsse.easysec.asn1.pkcs.RSAPrivateKey(getModulus(), ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
    }

    public boolean equals(Object o) {
        if (!(o instanceof RSAPrivateKey)) {
            return false;
        }
        if (o == this) {
            return true;
        }
        RSAPrivateKey key = (RSAPrivateKey) o;
        return getModulus().equals(key.getModulus()) && getPrivateExponent().equals(key.getPrivateExponent());
    }

    public int hashCode() {
        return getModulus().hashCode() ^ getPrivateExponent().hashCode();
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

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.modulus = (BigInteger) in.readObject();
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
        this.attrCarrier.readObject(in);
        this.privateExponent = (BigInteger) in.readObject();
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(this.modulus);
        this.attrCarrier.writeObject(out);
        out.writeObject(this.privateExponent);
    }
}
