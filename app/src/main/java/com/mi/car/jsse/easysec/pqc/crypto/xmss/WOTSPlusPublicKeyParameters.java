package com.mi.car.jsse.easysec.pqc.crypto.xmss;

/* access modifiers changed from: package-private */
public final class WOTSPlusPublicKeyParameters {
    private final byte[][] publicKey;

    protected WOTSPlusPublicKeyParameters(WOTSPlusParameters params, byte[][] publicKey2) {
        if (params == null) {
            throw new NullPointerException("params == null");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey == null");
        } else if (XMSSUtil.hasNullPointer(publicKey2)) {
            throw new NullPointerException("publicKey byte array == null");
        } else if (publicKey2.length != params.getLen()) {
            throw new IllegalArgumentException("wrong publicKey size");
        } else {
            for (byte[] bArr : publicKey2) {
                if (bArr.length != params.getTreeDigestSize()) {
                    throw new IllegalArgumentException("wrong publicKey format");
                }
            }
            this.publicKey = XMSSUtil.cloneArray(publicKey2);
        }
    }

    /* access modifiers changed from: protected */
    public byte[][] toByteArray() {
        return XMSSUtil.cloneArray(this.publicKey);
    }
}
