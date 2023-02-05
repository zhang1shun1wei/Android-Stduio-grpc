package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;

class LMOtsPrivateKey {
    private final LMOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] masterSecret;

    public LMOtsPrivateKey(LMOtsParameters parameter, byte[] i, int q, byte[] masterSecret) {
        this.parameter = parameter;
        this.I = i;
        this.q = q;
        this.masterSecret = masterSecret;
    }

    LMSContext getSignatureContext(LMSigParameters sigParams, byte[][] path) {
        byte[] C = new byte[32];
        SeedDerive derive = this.getDerivationFunction();
        derive.setJ(-3);
        derive.deriveSeed(C, false);
        Digest ctx = DigestUtil.getDigest(this.parameter.getDigestOID());
        LmsUtils.byteArray(this.getI(), ctx);
        LmsUtils.u32str(this.getQ(), ctx);
        LmsUtils.u16str((short)-32383, ctx);
        LmsUtils.byteArray(C, ctx);
        return new LMSContext(this, sigParams, ctx, C, path);
    }

    SeedDerive getDerivationFunction() {
        SeedDerive derive = new SeedDerive(this.I, this.masterSecret, DigestUtil.getDigest(this.parameter.getDigestOID()));
        derive.setQ(this.q);
        return derive;
    }

    public LMOtsParameters getParameter() {
        return this.parameter;
    }

    public byte[] getI() {
        return this.I;
    }

    public int getQ() {
        return this.q;
    }

    public byte[] getMasterSecret() {
        return this.masterSecret;
    }
}
