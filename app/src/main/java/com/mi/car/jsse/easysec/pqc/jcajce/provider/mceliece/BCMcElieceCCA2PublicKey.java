package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.jcajce.util.MessageDigestUtils;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCMcElieceCCA2PublicKey implements CipherParameters, PublicKey {
    private static final long serialVersionUID = 1;
    private transient McElieceCCA2PublicKeyParameters params;

    public BCMcElieceCCA2PublicKey(McElieceCCA2PublicKeyParameters params2) {
        this.params = params2;
    }

    private void init(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
        this.params = (McElieceCCA2PublicKeyParameters) PublicKeyFactory.createKey(publicKeyInfo);
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
        return this.params.getT();
    }

    public GF2Matrix getG() {
        return this.params.getG();
    }

    public String toString() {
        return (("McEliecePublicKey:\n" + " length of the code         : " + this.params.getN() + "\n") + " error correction capability: " + this.params.getT() + "\n") + " generator matrix           : " + this.params.getG().toString();
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof BCMcElieceCCA2PublicKey)) {
            return false;
        }
        BCMcElieceCCA2PublicKey otherKey = (BCMcElieceCCA2PublicKey) other;
        if (this.params.getN() == otherKey.getN() && this.params.getT() == otherKey.getT() && this.params.getG().equals(otherKey.getG())) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return ((this.params.getN() + (this.params.getT() * 37)) * 37) + this.params.getG().hashCode();
    }

    public byte[] getEncoded() {
        try {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2), new McElieceCCA2PublicKey(this.params.getN(), this.params.getT(), this.params.getG(), MessageDigestUtils.getDigestAlgID(this.params.getDigest()))).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "X.509";
    }

    /* access modifiers changed from: package-private */
    public AsymmetricKeyParameter getKeyParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        init(SubjectPublicKeyInfo.getInstance((byte[]) in.readObject()));
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
