package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.util.Arrays;

public class CMCEPrivateKeyParameters extends CMCEKeyParameters {
    private final byte[] privateKey;

    public byte[] getPrivateKey() {
        return Arrays.clone(this.privateKey);
    }

    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] privateKey2) {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey2);
    }

    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] delta, byte[] C, byte[] g, byte[] alpha, byte[] s) {
        super(true, params);
        this.privateKey = new byte[(delta.length + C.length + g.length + alpha.length + s.length)];
        System.arraycopy(delta, 0, this.privateKey, 0, delta.length);
        int offset = 0 + delta.length;
        System.arraycopy(C, 0, this.privateKey, offset, C.length);
        int offset2 = offset + C.length;
        System.arraycopy(g, 0, this.privateKey, offset2, g.length);
        int offset3 = offset2 + g.length;
        System.arraycopy(alpha, 0, this.privateKey, offset3, alpha.length);
        System.arraycopy(s, 0, this.privateKey, offset3 + alpha.length, s.length);
    }

    public byte[] reconstructPublicKey() {
        CMCEEngine engine = getParameters().getEngine();
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.generate_public_key_from_private_key(this.privateKey);
        return pk;
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.privateKey);
    }

    public byte[] getDelta() {
        return Arrays.copyOfRange(this.privateKey, 0, 32);
    }

    public byte[] getC() {
        return Arrays.copyOfRange(this.privateKey, 32, 40);
    }

    public byte[] getG() {
        return Arrays.copyOfRange(this.privateKey, 40, (getParameters().getT() * 2) + 40);
    }

    public byte[] getAlpha() {
        return Arrays.copyOfRange(this.privateKey, (getParameters().getT() * 2) + 40, this.privateKey.length - 32);
    }

    public byte[] getS() {
        return Arrays.copyOfRange(this.privateKey, this.privateKey.length - 32, this.privateKey.length);
    }
}
