package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Memoable;
import java.util.Hashtable;

public class HMac implements Mac {
    private static final byte IPAD = 54;
    private static final byte OPAD = 92;
    private static Hashtable blockLengths = new Hashtable();
    private int blockLength;
    private Digest digest;
    private int digestSize;
    private byte[] inputPad;
    private Memoable ipadState;
    private Memoable opadState;
    private byte[] outputBuf;

    static {
        blockLengths.put("GOST3411", Integers.valueOf(32));
        blockLengths.put("MD2", Integers.valueOf(16));
        blockLengths.put("MD4", Integers.valueOf(64));
        blockLengths.put("MD5", Integers.valueOf(64));
        blockLengths.put("RIPEMD128", Integers.valueOf(64));
        blockLengths.put("RIPEMD160", Integers.valueOf(64));
        blockLengths.put(McElieceCCA2KeyGenParameterSpec.SHA1, Integers.valueOf(64));
        blockLengths.put(McElieceCCA2KeyGenParameterSpec.SHA224, Integers.valueOf(64));
        blockLengths.put("SHA-256", Integers.valueOf(64));
        blockLengths.put(McElieceCCA2KeyGenParameterSpec.SHA384, Integers.valueOf(128));
        blockLengths.put("SHA-512", Integers.valueOf(128));
        blockLengths.put("Tiger", Integers.valueOf(64));
        blockLengths.put("Whirlpool", Integers.valueOf(64));
    }

    private static int getByteLength(Digest digest2) {
        if (digest2 instanceof ExtendedDigest) {
            return ((ExtendedDigest) digest2).getByteLength();
        }
        Integer b = (Integer) blockLengths.get(digest2.getAlgorithmName());
        if (b != null) {
            return b.intValue();
        }
        throw new IllegalArgumentException("unknown digest passed: " + digest2.getAlgorithmName());
    }

    public HMac(Digest digest2) {
        this(digest2, getByteLength(digest2));
    }

    private HMac(Digest digest2, int byteLength) {
        this.digest = digest2;
        this.digestSize = digest2.getDigestSize();
        this.blockLength = byteLength;
        this.inputPad = new byte[this.blockLength];
        this.outputBuf = new byte[(this.blockLength + this.digestSize)];
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return this.digest.getAlgorithmName() + "/HMAC";
    }

    public Digest getUnderlyingDigest() {
        return this.digest;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) {
        this.digest.reset();
        byte[] key = ((KeyParameter) params).getKey();
        int keyLength = key.length;
        if (keyLength > this.blockLength) {
            this.digest.update(key, 0, keyLength);
            this.digest.doFinal(this.inputPad, 0);
            keyLength = this.digestSize;
        } else {
            System.arraycopy(key, 0, this.inputPad, 0, keyLength);
        }
        for (int i = keyLength; i < this.inputPad.length; i++) {
            this.inputPad[i] = 0;
        }
        System.arraycopy(this.inputPad, 0, this.outputBuf, 0, this.blockLength);
        xorPad(this.inputPad, this.blockLength, IPAD);
        xorPad(this.outputBuf, this.blockLength, OPAD);
        if (this.digest instanceof Memoable) {
            this.opadState = ((Memoable) this.digest).copy();
            ((Digest) this.opadState).update(this.outputBuf, 0, this.blockLength);
        }
        this.digest.update(this.inputPad, 0, this.inputPad.length);
        if (this.digest instanceof Memoable) {
            this.ipadState = ((Memoable) this.digest).copy();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.digestSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) {
        this.digest.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) {
        this.digest.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) {
        this.digest.doFinal(this.outputBuf, this.blockLength);
        if (this.opadState != null) {
            ((Memoable) this.digest).reset(this.opadState);
            this.digest.update(this.outputBuf, this.blockLength, this.digest.getDigestSize());
        } else {
            this.digest.update(this.outputBuf, 0, this.outputBuf.length);
        }
        int len = this.digest.doFinal(out, outOff);
        for (int i = this.blockLength; i < this.outputBuf.length; i++) {
            this.outputBuf[i] = 0;
        }
        if (this.ipadState != null) {
            ((Memoable) this.digest).reset(this.ipadState);
        } else {
            this.digest.update(this.inputPad, 0, this.inputPad.length);
        }
        return len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        this.digest.reset();
        this.digest.update(this.inputPad, 0, this.inputPad.length);
    }

    private static void xorPad(byte[] pad, int len, byte n) {
        for (int i = 0; i < len; i++) {
            pad[i] = (byte) (pad[i] ^ n);
        }
    }
}
