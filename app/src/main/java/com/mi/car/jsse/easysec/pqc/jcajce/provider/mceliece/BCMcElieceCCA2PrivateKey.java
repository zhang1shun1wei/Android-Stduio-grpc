package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.jcajce.util.MessageDigestUtils;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCMcElieceCCA2PrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1;
    private transient McElieceCCA2PrivateKeyParameters params;

    public BCMcElieceCCA2PrivateKey(McElieceCCA2PrivateKeyParameters params2) {
        this.params = params2;
    }

    private void init(PrivateKeyInfo privateKeyInfo) throws IOException {
        this.params = (McElieceCCA2PrivateKeyParameters) PrivateKeyFactory.createKey(privateKeyInfo);
    }

    public String getAlgorithm() {
        return "McEliece-CCA2";
    }

    public int getN() {
        return this.params.getN();
    }

    public int getK() {
        return this.params.getK();
    }

    public int getT() {
        return this.params.getGoppaPoly().getDegree();
    }

    public GF2mField getField() {
        return this.params.getField();
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.params.getGoppaPoly();
    }

    public Permutation getP() {
        return this.params.getP();
    }

    public GF2Matrix getH() {
        return this.params.getH();
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.params.getQInv();
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof BCMcElieceCCA2PrivateKey)) {
            return false;
        }
        BCMcElieceCCA2PrivateKey otherKey = (BCMcElieceCCA2PrivateKey) other;
        if (getN() != otherKey.getN() || getK() != otherKey.getK() || !getField().equals(otherKey.getField()) || !getGoppaPoly().equals(otherKey.getGoppaPoly()) || !getP().equals(otherKey.getP()) || !getH().equals(otherKey.getH())) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (((((((((this.params.getK() * 37) + this.params.getN()) * 37) + this.params.getField().hashCode()) * 37) + this.params.getGoppaPoly().hashCode()) * 37) + this.params.getP().hashCode()) * 37) + this.params.getH().hashCode();
    }

    public byte[] getEncoded() {
        try {
            return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2), new McElieceCCA2PrivateKey(getN(), getK(), getField(), getGoppaPoly(), getP(), MessageDigestUtils.getDigestAlgID(this.params.getDigest()))).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "PKCS#8";
    }

    /* access modifiers changed from: package-private */
    public AsymmetricKeyParameter getKeyParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        init(PrivateKeyInfo.getInstance((byte[]) in.readObject()));
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
