package com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow;

import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.RainbowPublicKey;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.RainbowUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.KeyUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.RainbowPublicKeySpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.PublicKey;

public class BCRainbowPublicKey implements PublicKey {
    private static final long serialVersionUID = 1;
    private short[][] coeffquadratic;
    private short[] coeffscalar;
    private short[][] coeffsingular;
    private int docLength;
    private RainbowParameters rainbowParams;

    public BCRainbowPublicKey(int docLength2, short[][] coeffQuadratic, short[][] coeffSingular, short[] coeffScalar) {
        this.docLength = docLength2;
        this.coeffquadratic = coeffQuadratic;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;
    }

    public BCRainbowPublicKey(RainbowPublicKeySpec keySpec) {
        this(keySpec.getDocLength(), keySpec.getCoeffQuadratic(), keySpec.getCoeffSingular(), keySpec.getCoeffScalar());
    }

    public BCRainbowPublicKey(RainbowPublicKeyParameters params) {
        this(params.getDocLength(), params.getCoeffQuadratic(), params.getCoeffSingular(), params.getCoeffScalar());
    }

    public int getDocLength() {
        return this.docLength;
    }

    public short[][] getCoeffQuadratic() {
        return this.coeffquadratic;
    }

    public short[][] getCoeffSingular() {
        short[][] copy = new short[this.coeffsingular.length][];
        for (int i = 0; i != this.coeffsingular.length; i++) {
            copy[i] = Arrays.clone(this.coeffsingular[i]);
        }
        return copy;
    }

    public short[] getCoeffScalar() {
        return Arrays.clone(this.coeffscalar);
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof BCRainbowPublicKey)) {
            return false;
        }
        BCRainbowPublicKey otherKey = (BCRainbowPublicKey) other;
        if (this.docLength != otherKey.getDocLength() || !RainbowUtil.equals(this.coeffquadratic, otherKey.getCoeffQuadratic()) || !RainbowUtil.equals(this.coeffsingular, otherKey.getCoeffSingular()) || !RainbowUtil.equals(this.coeffscalar, otherKey.getCoeffScalar())) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (((((this.docLength * 37) + Arrays.hashCode(this.coeffquadratic)) * 37) + Arrays.hashCode(this.coeffsingular)) * 37) + Arrays.hashCode(this.coeffscalar);
    }

    public final String getAlgorithm() {
        return "Rainbow";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.rainbow, DERNull.INSTANCE), new RainbowPublicKey(this.docLength, this.coeffquadratic, this.coeffsingular, this.coeffscalar));
    }
}
