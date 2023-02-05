package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.asn1.McEliecePublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import java.io.IOException;
import java.security.PublicKey;

public class BCMcEliecePublicKey implements PublicKey {
    private static final long serialVersionUID = 1;
    private McEliecePublicKeyParameters params;

    public BCMcEliecePublicKey(McEliecePublicKeyParameters params2) {
        this.params = params2;
    }

    public String getAlgorithm() {
        return "McEliece";
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
        return (("McEliecePublicKey:\n" + " length of the code         : " + this.params.getN() + "\n") + " error correction capability: " + this.params.getT() + "\n") + " generator matrix           : " + this.params.getG();
    }

    public boolean equals(Object other) {
        if (!(other instanceof BCMcEliecePublicKey)) {
            return false;
        }
        BCMcEliecePublicKey otherKey = (BCMcEliecePublicKey) other;
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
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.mcEliece), new McEliecePublicKey(this.params.getN(), this.params.getT(), this.params.getG())).getEncoded();
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
}
