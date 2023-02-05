package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;

public class ParallelHash implements Xof, Digest {
    private static final byte[] N_PARALLEL_HASH = Strings.toByteArray("ParallelHash");
    private final int B;
    private final int bitLength;
    private int bufOff;
    private final byte[] buffer;
    private final CSHAKEDigest compressor;
    private final byte[] compressorBuffer;
    private final CSHAKEDigest cshake;
    private boolean firstOutput;
    private int nCount;
    private final int outputLength;

    public ParallelHash(int bitLength2, byte[] S, int B2) {
        this(bitLength2, S, B2, bitLength2 * 2);
    }

    public ParallelHash(int bitLength2, byte[] S, int B2, int outputSize) {
        this.cshake = new CSHAKEDigest(bitLength2, N_PARALLEL_HASH, S);
        this.compressor = new CSHAKEDigest(bitLength2, new byte[0], new byte[0]);
        this.bitLength = bitLength2;
        this.B = B2;
        this.outputLength = (outputSize + 7) / 8;
        this.buffer = new byte[B2];
        this.compressorBuffer = new byte[((bitLength2 * 2) / 8)];
        reset();
    }

    public ParallelHash(ParallelHash source) {
        this.cshake = new CSHAKEDigest(source.cshake);
        this.compressor = new CSHAKEDigest(source.compressor);
        this.bitLength = source.bitLength;
        this.B = source.B;
        this.outputLength = source.outputLength;
        this.buffer = Arrays.clone(source.buffer);
        this.compressorBuffer = Arrays.clone(source.compressorBuffer);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "ParallelHash" + this.cshake.getAlgorithmName().substring(6);
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
        byte[] bArr = this.buffer;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = in;
        if (this.bufOff == this.buffer.length) {
            compress();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        int len2 = Math.max(0, len);
        int i = 0;
        if (this.bufOff != 0) {
            int i2 = 0;
            while (i2 < len2 && this.bufOff != this.buffer.length) {
                byte[] bArr = this.buffer;
                int i3 = this.bufOff;
                this.bufOff = i3 + 1;
                bArr[i3] = in[inOff + i2];
                i2++;
            }
            if (this.bufOff == this.buffer.length) {
                compress();
            }
            i = i2;
        }
        if (i < len2) {
            while (len2 - i > this.B) {
                compress(in, inOff + i, this.B);
                i += this.B;
            }
        }
        for (int i4 = i; i4 < len2; i4++) {
            update(in[inOff + i4]);
        }
    }

    private void compress() {
        compress(this.buffer, 0, this.bufOff);
        this.bufOff = 0;
    }

    private void compress(byte[] buf, int offSet, int len) {
        this.compressor.update(buf, offSet, len);
        this.compressor.doFinal(this.compressorBuffer, 0, this.compressorBuffer.length);
        this.cshake.update(this.compressorBuffer, 0, this.compressorBuffer.length);
        this.nCount++;
    }

    private void wrapUp(int outputSize) {
        if (this.bufOff != 0) {
            compress();
        }
        byte[] nOut = XofUtils.rightEncode((long) this.nCount);
        byte[] encOut = XofUtils.rightEncode((long) (outputSize * 8));
        this.cshake.update(nOut, 0, nOut.length);
        this.cshake.update(encOut, 0, encOut.length);
        this.firstOutput = false;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.firstOutput) {
            wrapUp(this.outputLength);
        }
        int rv = this.cshake.doFinal(out, outOff, getDigestSize());
        reset();
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doFinal(byte[] out, int outOff, int outLen) {
        if (this.firstOutput) {
            wrapUp(this.outputLength);
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
        Arrays.clear(this.buffer);
        byte[] hdr = XofUtils.leftEncode((long) this.B);
        this.cshake.update(hdr, 0, hdr.length);
        this.nCount = 0;
        this.bufOff = 0;
        this.firstOutput = true;
    }
}
