package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.asn1.McEliecePrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import java.io.IOException;
import java.security.PrivateKey;

public class BCMcEliecePrivateKey implements CipherParameters, PrivateKey {
    private static final long serialVersionUID = 1;
    private McEliecePrivateKeyParameters params;

    public BCMcEliecePrivateKey(McEliecePrivateKeyParameters params2) {
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

    public GF2mField getField() {
        return this.params.getField();
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.params.getGoppaPoly();
    }

    public GF2Matrix getSInv() {
        return this.params.getSInv();
    }

    public Permutation getP1() {
        return this.params.getP1();
    }

    public Permutation getP2() {
        return this.params.getP2();
    }

    public GF2Matrix getH() {
        return this.params.getH();
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.params.getQInv();
    }

    public boolean equals(Object other) {
        if (!(other instanceof BCMcEliecePrivateKey)) {
            return false;
        }
        BCMcEliecePrivateKey otherKey = (BCMcEliecePrivateKey) other;
        if (getN() != otherKey.getN() || getK() != otherKey.getK() || !getField().equals(otherKey.getField()) || !getGoppaPoly().equals(otherKey.getGoppaPoly()) || !getSInv().equals(otherKey.getSInv()) || !getP1().equals(otherKey.getP1()) || !getP2().equals(otherKey.getP2())) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (((((((((((this.params.getK() * 37) + this.params.getN()) * 37) + this.params.getField().hashCode()) * 37) + this.params.getGoppaPoly().hashCode()) * 37) + this.params.getP1().hashCode()) * 37) + this.params.getP2().hashCode()) * 37) + this.params.getSInv().hashCode();
    }

    public byte[] getEncoded() {
        try {
            try {
                return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.mcEliece), new McEliecePrivateKey(this.params.getN(), this.params.getK(), this.params.getField(), this.params.getGoppaPoly(), this.params.getP1(), this.params.getP2(), this.params.getSInv())).getEncoded();
            } catch (IOException e) {
                return null;
            }
        } catch (Exception e2) {
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
}
