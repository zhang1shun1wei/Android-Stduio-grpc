package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.digests.Blake3Digest;
import com.mi.car.jsse.easysec.crypto.params.Blake3Parameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;

public class Blake3Mac implements Mac {
    private final Blake3Digest theDigest;

    public Blake3Mac(Blake3Digest pDigest) {
        this.theDigest = pDigest;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return this.theDigest.getAlgorithmName() + "Mac";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters pParams) {
        CipherParameters myParams = pParams;
        if (myParams instanceof KeyParameter) {
            myParams = Blake3Parameters.key(((KeyParameter) myParams).getKey());
        }
        if (!(myParams instanceof Blake3Parameters)) {
            throw new IllegalArgumentException("Invalid parameter passed to Blake3Mac init - " + pParams.getClass().getName());
        }
        Blake3Parameters myBlakeParams = (Blake3Parameters) myParams;
        if (myBlakeParams.getKey() == null) {
            throw new IllegalArgumentException("Blake3Mac requires a key parameter.");
        }
        this.theDigest.init(myBlakeParams);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.theDigest.getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) {
        this.theDigest.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) {
        this.theDigest.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) {
        return this.theDigest.doFinal(out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        this.theDigest.reset();
    }
}
