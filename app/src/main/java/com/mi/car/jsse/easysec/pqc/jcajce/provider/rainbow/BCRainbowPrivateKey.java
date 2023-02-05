package com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow;

import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.RainbowPrivateKey;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.Layer;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.RainbowUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.RainbowPrivateKeySpec;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;

public class BCRainbowPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1;
    private short[][] A1inv;
    private short[][] A2inv;
    private short[] b1;
    private short[] b2;
    private Layer[] layers;
    private int[] vi;

    public BCRainbowPrivateKey(short[][] A1inv2, short[] b12, short[][] A2inv2, short[] b22, int[] vi2, Layer[] layers2) {
        this.A1inv = A1inv2;
        this.b1 = b12;
        this.A2inv = A2inv2;
        this.b2 = b22;
        this.vi = vi2;
        this.layers = layers2;
    }

    public BCRainbowPrivateKey(RainbowPrivateKeySpec keySpec) {
        this(keySpec.getInvA1(), keySpec.getB1(), keySpec.getInvA2(), keySpec.getB2(), keySpec.getVi(), keySpec.getLayers());
    }

    public BCRainbowPrivateKey(RainbowPrivateKeyParameters params) {
        this(params.getInvA1(), params.getB1(), params.getInvA2(), params.getB2(), params.getVi(), params.getLayers());
    }

    public short[][] getInvA1() {
        return this.A1inv;
    }

    public short[] getB1() {
        return this.b1;
    }

    public short[] getB2() {
        return this.b2;
    }

    public short[][] getInvA2() {
        return this.A2inv;
    }

    public Layer[] getLayers() {
        return this.layers;
    }

    public int[] getVi() {
        return this.vi;
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof BCRainbowPrivateKey)) {
            return false;
        }
        BCRainbowPrivateKey otherKey = (BCRainbowPrivateKey) other;
        boolean eq = ((((1 != 0 && RainbowUtil.equals(this.A1inv, otherKey.getInvA1())) && RainbowUtil.equals(this.A2inv, otherKey.getInvA2())) && RainbowUtil.equals(this.b1, otherKey.getB1())) && RainbowUtil.equals(this.b2, otherKey.getB2())) && Arrays.equals(this.vi, otherKey.getVi());
        if (this.layers.length != otherKey.getLayers().length) {
            return false;
        }
        for (int i = this.layers.length - 1; i >= 0; i--) {
            eq &= this.layers[i].equals(otherKey.getLayers()[i]);
        }
        return eq;
    }

    public int hashCode() {
        int hash = (((((((((this.layers.length * 37) + com.mi.car.jsse.easysec.util.Arrays.hashCode(this.A1inv)) * 37) + com.mi.car.jsse.easysec.util.Arrays.hashCode(this.b1)) * 37) + com.mi.car.jsse.easysec.util.Arrays.hashCode(this.A2inv)) * 37) + com.mi.car.jsse.easysec.util.Arrays.hashCode(this.b2)) * 37) + com.mi.car.jsse.easysec.util.Arrays.hashCode(this.vi);
        for (int i = this.layers.length - 1; i >= 0; i--) {
            hash = (hash * 37) + this.layers[i].hashCode();
        }
        return hash;
    }

    public final String getAlgorithm() {
        return "Rainbow";
    }

    public byte[] getEncoded() {
        try {
            try {
                return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.rainbow, DERNull.INSTANCE), new RainbowPrivateKey(this.A1inv, this.b1, this.A2inv, this.b2, this.vi, this.layers)).getEncoded();
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
}
