package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.pqc.crypto.ExhaustedPrivateKeyException;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.WeakHashMap;

public class LMSPrivateKeyParameters extends LMSKeyParameters implements LMSContextBasedSigner {
    private static LMSPrivateKeyParameters.CacheKey T1 = new LMSPrivateKeyParameters.CacheKey(1);
    private static LMSPrivateKeyParameters.CacheKey[] internedKeys = new LMSPrivateKeyParameters.CacheKey[129];
    private final byte[] I;
    private final LMSigParameters parameters;
    private final LMOtsParameters otsParameters;
    private final int maxQ;
    private final byte[] masterSecret;
    private final Map<LMSPrivateKeyParameters.CacheKey, byte[]> tCache;
    private final int maxCacheR;
    private final Digest tDigest;
    private int q;
    private LMSPublicKeyParameters publicKey;

    public LMSPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I, int maxQ, byte[] masterSecret) {
        super(true);
        this.parameters = lmsParameter;
        this.otsParameters = otsParameters;
        this.q = q;
        this.I = Arrays.clone(I);
        this.maxQ = maxQ;
        this.masterSecret = Arrays.clone(masterSecret);
        this.maxCacheR = 1 << this.parameters.getH() + 1;
        this.tCache = new WeakHashMap();
        this.tDigest = DigestUtil.getDigest(lmsParameter.getDigestOID());
    }

    private LMSPrivateKeyParameters(LMSPrivateKeyParameters parent, int q, int maxQ) {
        super(true);
        this.parameters = parent.parameters;
        this.otsParameters = parent.otsParameters;
        this.q = q;
        this.I = parent.I;
        this.maxQ = maxQ;
        this.masterSecret = parent.masterSecret;
        this.maxCacheR = 1 << this.parameters.getH();
        this.tCache = parent.tCache;
        this.tDigest = DigestUtil.getDigest(this.parameters.getDigestOID());
        this.publicKey = parent.publicKey;
    }

    public static LMSPrivateKeyParameters getInstance(byte[] privEnc, byte[] pubEnc) throws IOException {
        LMSPrivateKeyParameters pKey = getInstance(privEnc);
        pKey.publicKey = LMSPublicKeyParameters.getInstance(pubEnc);
        return pKey;
    }

    public static LMSPrivateKeyParameters getInstance(Object src) throws IOException {
        if (src instanceof LMSPrivateKeyParameters) {
            return (LMSPrivateKeyParameters)src;
        } else {
            DataInputStream in;
            if (src instanceof DataInputStream) {
                in = (DataInputStream)src;
                if (in.readInt() != 0) {
                    throw new IllegalStateException("expected version 0 lms private key");
                } else {
                    LMSigParameters parameter = LMSigParameters.getParametersForType(in.readInt());
                    LMOtsParameters otsParameter = LMOtsParameters.getParametersForType(in.readInt());
                    byte[] I = new byte[16];
                    in.readFully(I);
                    int q = in.readInt();
                    int maxQ = in.readInt();
                    int l = in.readInt();
                    if (l < 0) {
                        throw new IllegalStateException("secret length less than zero");
                    } else if (l > in.available()) {
                        throw new IOException("secret length exceeded " + in.available());
                    } else {
                        byte[] masterSecret = new byte[l];
                        in.readFully(masterSecret);
                        return new LMSPrivateKeyParameters(parameter, otsParameter, q, I, maxQ, masterSecret);
                    }
                }
            } else if (src instanceof byte[]) {
                in = null;

                LMSPrivateKeyParameters var2;
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
    }

    LMOtsPrivateKey getCurrentOTSKey() {
        synchronized(this) {
            if (this.q >= this.maxQ) {
                throw new ExhaustedPrivateKeyException("ots private keys expired");
            } else {
                return new LMOtsPrivateKey(this.otsParameters, this.I, this.q, this.masterSecret);
            }
        }
    }

    public synchronized int getIndex() {
        return this.q;
    }

    synchronized void incIndex() {
        ++this.q;
    }

    public LMSContext generateLMSContext() {
        LMSigParameters lmsParameter = this.getSigParameters();
        int h = lmsParameter.getH();
        int q = this.getIndex();
        LMOtsPrivateKey otsPk = this.getNextOtsPrivateKey();
        int i = 0;
        int r = (1 << h) + q;

        byte[][] path;
        for(path = new byte[h][]; i < h; ++i) {
            int tmp = r / (1 << i) ^ 1;
            path[i] = this.findT(tmp);
        }

        return otsPk.getSignatureContext(this.getSigParameters(), path);
    }

    public byte[] generateSignature(LMSContext context) {
        try {
            return LMS.generateSign(context).getEncoded();
        } catch (IOException var3) {
            throw new IllegalStateException("unable to encode signature: " + var3.getMessage(), var3);
        }
    }

    LMOtsPrivateKey getNextOtsPrivateKey() {
        synchronized(this) {
            if (this.q >= this.maxQ) {
                throw new ExhaustedPrivateKeyException("ots private key exhausted");
            } else {
                LMOtsPrivateKey otsPrivateKey = new LMOtsPrivateKey(this.otsParameters, this.I, this.q, this.masterSecret);
                this.incIndex();
                return otsPrivateKey;
            }
        }
    }

    public LMSPrivateKeyParameters extractKeyShard(int usageCount) {
        synchronized(this) {
            if (this.q + usageCount >= this.maxQ) {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            } else {
                LMSPrivateKeyParameters keyParameters = new LMSPrivateKeyParameters(this, this.q, this.q + usageCount);
                this.q += usageCount;
                return keyParameters;
            }
        }
    }

    public LMSigParameters getSigParameters() {
        return this.parameters;
    }

    public LMOtsParameters getOtsParameters() {
        return this.otsParameters;
    }

    public byte[] getI() {
        return Arrays.clone(this.I);
    }

    public byte[] getMasterSecret() {
        return Arrays.clone(this.masterSecret);
    }

    public long getUsagesRemaining() {
        return (long)(this.maxQ - this.q);
    }

    public LMSPublicKeyParameters getPublicKey() {
        synchronized(this) {
            if (this.publicKey == null) {
                this.publicKey = new LMSPublicKeyParameters(this.parameters, this.otsParameters, this.findT(T1), this.I);
            }

            return this.publicKey;
        }
    }

    byte[] findT(int r) {
        return r < this.maxCacheR ? this.findT(r < internedKeys.length ? internedKeys[r] : new LMSPrivateKeyParameters.CacheKey(r)) : this.calcT(r);
    }

    private byte[] findT(LMSPrivateKeyParameters.CacheKey key) {
        synchronized(this.tCache) {
            byte[] t = (byte[])this.tCache.get(key);
            if (t != null) {
                return t;
            } else {
                t = this.calcT(key.index);
                this.tCache.put(key, t);
                return t;
            }
        }
    }

    private byte[] calcT(int r) {
        int h = this.getSigParameters().getH();
        int twoToh = 1 << h;
        byte[] T;
        byte[] t2r;
        if (r >= twoToh) {
            LmsUtils.byteArray(this.getI(), this.tDigest);
            LmsUtils.u32str(r, this.tDigest);
            LmsUtils.u16str((short)-32126, this.tDigest);
            t2r = LM_OTS.lms_ots_generatePublicKey(this.getOtsParameters(), this.getI(), r - twoToh, this.getMasterSecret());
            LmsUtils.byteArray(t2r, this.tDigest);
            T = new byte[this.tDigest.getDigestSize()];
            this.tDigest.doFinal(T, 0);
            return T;
        } else {
            t2r = this.findT(2 * r);
            byte[] t2rPlus1 = this.findT(2 * r + 1);
            LmsUtils.byteArray(this.getI(), this.tDigest);
            LmsUtils.u32str(r, this.tDigest);
            LmsUtils.u16str((short)-31869, this.tDigest);
            LmsUtils.byteArray(t2r, this.tDigest);
            LmsUtils.byteArray(t2rPlus1, this.tDigest);
            T = new byte[this.tDigest.getDigestSize()];
            this.tDigest.doFinal(T, 0);
            return T;
        }
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o != null && this.getClass() == o.getClass()) {
            LMSPrivateKeyParameters that = (LMSPrivateKeyParameters)o;
            if (this.q != that.q) {
                return false;
            } else if (this.maxQ != that.maxQ) {
                return false;
            } else if (!Arrays.areEqual(this.I, that.I)) {
                return false;
            } else {
                if (this.parameters != null) {
                    if (!this.parameters.equals(that.parameters)) {
                        return false;
                    }
                } else if (that.parameters != null) {
                    return false;
                }

                label44: {
                    if (this.otsParameters != null) {
                        if (this.otsParameters.equals(that.otsParameters)) {
                            break label44;
                        }
                    } else if (that.otsParameters == null) {
                        break label44;
                    }

                    return false;
                }

                if (!Arrays.areEqual(this.masterSecret, that.masterSecret)) {
                    return false;
                } else if (this.publicKey != null && that.publicKey != null) {
                    return this.publicKey.equals(that.publicKey);
                } else {
                    return true;
                }
            }
        } else {
            return false;
        }
    }

    public int hashCode() {
        int result = this.q;
        result = 31 * result + Arrays.hashCode(this.I);
        result = 31 * result + (this.parameters != null ? this.parameters.hashCode() : 0);
        result = 31 * result + (this.otsParameters != null ? this.otsParameters.hashCode() : 0);
        result = 31 * result + this.maxQ;
        result = 31 * result + Arrays.hashCode(this.masterSecret);
        result = 31 * result + (this.publicKey != null ? this.publicKey.hashCode() : 0);
        return result;
    }

    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(0).u32str(this.parameters.getType()).u32str(this.otsParameters.getType()).bytes(this.I).u32str(this.q).u32str(this.maxQ).u32str(this.masterSecret.length).bytes(this.masterSecret).build();
    }

    static {
        internedKeys[1] = T1;

        for(int i = 2; i < internedKeys.length; ++i) {
            internedKeys[i] = new LMSPrivateKeyParameters.CacheKey(i);
        }

    }

    private static class CacheKey {
        private final int index;

        CacheKey(int index) {
            this.index = index;
        }

        public int hashCode() {
            return this.index;
        }

        public boolean equals(Object o) {
            if (o instanceof LMSPrivateKeyParameters.CacheKey) {
                return ((LMSPrivateKeyParameters.CacheKey)o).index == this.index;
            } else {
                return false;
            }
        }
    }
}
