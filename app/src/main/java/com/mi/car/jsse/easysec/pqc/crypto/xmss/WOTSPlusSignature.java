package com.mi.car.jsse.easysec.pqc.crypto.xmss;

/* access modifiers changed from: package-private */
public final class WOTSPlusSignature {
    private byte[][] signature;

    protected WOTSPlusSignature(WOTSPlusParameters params, byte[][] signature2) {
        if (params == null) {
            throw new NullPointerException("params == null");
        } else if (signature2 == null) {
            throw new NullPointerException("signature == null");
        } else if (XMSSUtil.hasNullPointer(signature2)) {
            throw new NullPointerException("signature byte array == null");
        } else if (signature2.length != params.getLen()) {
            throw new IllegalArgumentException("wrong signature size");
        } else {
            for (byte[] bArr : signature2) {
                if (bArr.length != params.getTreeDigestSize()) {
                    throw new IllegalArgumentException("wrong signature format");
                }
            }
            this.signature = XMSSUtil.cloneArray(signature2);
        }
    }

    public byte[][] toByteArray() {
        return XMSSUtil.cloneArray(this.signature);
    }
}
