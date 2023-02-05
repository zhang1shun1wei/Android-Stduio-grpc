package com.mi.car.jsse.easysec.pqc.crypto.xmss;

final class WOTSPlusPrivateKeyParameters {
    private final byte[][] privateKey;

    protected WOTSPlusPrivateKeyParameters(WOTSPlusParameters params, byte[][] privateKey2) {
        if (params == null) {
            throw new NullPointerException("params == null");
        } else if (privateKey2 == null) {
            throw new NullPointerException("privateKey == null");
        } else if (XMSSUtil.hasNullPointer(privateKey2)) {
            throw new NullPointerException("privateKey byte array == null");
        } else if (privateKey2.length != params.getLen()) {
            throw new IllegalArgumentException("wrong privateKey format");
        } else {
            for (byte[] bArr : privateKey2) {
                if (bArr.length != params.getTreeDigestSize()) {
                    throw new IllegalArgumentException("wrong privateKey format");
                }
            }
            this.privateKey = XMSSUtil.cloneArray(privateKey2);
        }
    }

    /* access modifiers changed from: protected */
    public byte[][] toByteArray() {
        return XMSSUtil.cloneArray(this.privateKey);
    }
}
