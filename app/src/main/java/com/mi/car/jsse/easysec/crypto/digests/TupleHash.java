package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.util.Strings;

public class TupleHash implements Xof, Digest {
    private static final byte[] N_TUPLE_HASH = Strings.toByteArray("TupleHash");
    private final int bitLength;
    private final CSHAKEDigest cshake;
    private boolean firstOutput;
    private final int outputLength;

    public TupleHash(int bitLength2, byte[] S) {
        this(bitLength2, S, bitLength2 * 2);
    }

    public TupleHash(int bitLength2, byte[] S, int outputSize) {
        this.cshake = new CSHAKEDigest(bitLength2, N_TUPLE_HASH, S);
        this.bitLength = bitLength2;
        this.outputLength = (outputSize + 7) / 8;
        reset();
    }

    public TupleHash(TupleHash original) {
        this.cshake = new CSHAKEDigest(original.cshake);
        this.bitLength = this.cshake.fixedOutputLength;
        this.outputLength = (this.bitLength * 2) / 8;
        this.firstOutput = original.firstOutput;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "TupleHash" + this.cshake.getAlgorithmName().substring(6);
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.cshake.getByteLength();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.outputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) throws IllegalStateException {
        byte[] bytes = XofUtils.encode(in);
        this.cshake.update(bytes, 0, bytes.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        byte[] bytes = XofUtils.encode(in, inOff, len);
        this.cshake.update(bytes, 0, bytes.length);
    }

    private void wrapUp(int outputSize) {
        byte[] encOut = XofUtils.rightEncode(((long) outputSize) * 8);
        this.cshake.update(encOut, 0, encOut.length);
        this.firstOutput = false;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.firstOutput) {
            wrapUp(getDigestSize());
        }
        int rv = this.cshake.doFinal(out, outOff, getDigestSize());
        reset();
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doFinal(byte[] out, int outOff, int outLen) {
        if (this.firstOutput) {
            wrapUp(getDigestSize());
        }
        int rv = this.cshake.doFinal(out, outOff, outLen);
        reset();
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doOutput(byte[] out, int outOff, int outLen) {
        if (this.firstOutput) {
            wrapUp(0);
        }
        return this.cshake.doOutput(out, outOff, outLen);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.cshake.reset();
        this.firstOutput = true;
    }
}
