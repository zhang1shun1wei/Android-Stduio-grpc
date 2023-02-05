package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;

public class NullDigest implements Digest {
    private OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "NULL";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.bOut.size();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        this.bOut.write(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        this.bOut.write(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        int size = this.bOut.size();
        this.bOut.copy(out, outOff);
        reset();
        return size;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.bOut.reset();
    }

    /* access modifiers changed from: private */
    public static class OpenByteArrayOutputStream extends ByteArrayOutputStream {
        private OpenByteArrayOutputStream() {
        }

        public void reset() {
            super.reset();
            Arrays.clear(this.buf);
        }

        /* access modifiers changed from: package-private */
        public void copy(byte[] out, int outOff) {
            System.arraycopy(this.buf, 0, out, outOff, size());
        }
    }
}
