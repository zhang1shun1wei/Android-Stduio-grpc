package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Encodable;
import com.mi.car.jsse.easysec.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

class LMOtsPublicKey implements Encodable {
    private final LMOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] K;

    public LMOtsPublicKey(LMOtsParameters parameter, byte[] i, int q, byte[] k) {
        this.parameter = parameter;
        this.I = i;
        this.q = q;
        this.K = k;
    }

    public static LMOtsPublicKey getInstance(Object src) throws Exception {
        if (src instanceof LMOtsPublicKey) {
            return (LMOtsPublicKey)src;
        } else if (src instanceof DataInputStream) {
            LMOtsParameters parameter = LMOtsParameters.getParametersForType(((DataInputStream)src).readInt());
            byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);
            int q = ((DataInputStream)src).readInt();
            byte[] K = new byte[parameter.getN()];
            ((DataInputStream)src).readFully(K);
            return new LMOtsPublicKey(parameter, I, q, K);
        } else if (src instanceof byte[]) {
            DataInputStream in = null;

            LMOtsPublicKey var2;
            try {
                in = new DataInputStream(new ByteArrayInputStream((byte[])((byte[])src)));
                var2 = getInstance(in);
            } finally {
                if (in != null) {
                    in.close();
                }

            }

            return var2;
        } else if (src instanceof InputStream) {
            return getInstance(Streams.readAll((InputStream)src));
        } else {
            throw new IllegalArgumentException("cannot parse " + src);
        }
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

    public byte[] getK() {
        return this.K;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o != null && this.getClass() == o.getClass()) {
            LMOtsPublicKey that = (LMOtsPublicKey)o;
            if (this.q != that.q) {
                return false;
            } else {
                if (this.parameter != null) {
                    if (this.parameter.equals(that.parameter)) {
                        return !Arrays.equals(this.I, that.I) ? false : Arrays.equals(this.K, that.K);
                    }
                } else if (that.parameter == null) {
                    return !Arrays.equals(this.I, that.I) ? false : Arrays.equals(this.K, that.K);
                }

                return false;
            }
        } else {
            return false;
        }
    }

    public int hashCode() {
        int result = this.parameter != null ? this.parameter.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(this.I);
        result = 31 * result + this.q;
        result = 31 * result + Arrays.hashCode(this.K);
        return result;
    }

    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.parameter.getType()).bytes(this.I).u32str(this.q).bytes(this.K).build();
    }

    LMSContext createOtsContext(LMOtsSignature signature) {
        Digest ctx = DigestUtil.getDigest(this.parameter.getDigestOID());
        LmsUtils.byteArray(this.I, ctx);
        LmsUtils.u32str(this.q, ctx);
        LmsUtils.u16str((short)-32383, ctx);
        LmsUtils.byteArray(signature.getC(), ctx);
        return new LMSContext(this, signature, ctx);
    }

    LMSContext createOtsContext(LMSSignature signature) {
        Digest ctx = DigestUtil.getDigest(this.parameter.getDigestOID());
        LmsUtils.byteArray(this.I, ctx);
        LmsUtils.u32str(this.q, ctx);
        LmsUtils.u16str((short)-32383, ctx);
        LmsUtils.byteArray(signature.getOtsSignature().getC(), ctx);
        return new LMSContext(this, signature, ctx);
    }
}
