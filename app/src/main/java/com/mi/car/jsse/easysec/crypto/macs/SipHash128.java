package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.util.Pack;

public class SipHash128 extends SipHash {
    public SipHash128() {
    }

    public SipHash128(int c, int d) {
        super(c, d);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.macs.SipHash
    public String getAlgorithmName() {
        return "SipHash128-" + this.c + "-" + this.d;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.macs.SipHash
    public int getMacSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.macs.SipHash
    public long doFinal() throws DataLengthException, IllegalStateException {
        throw new UnsupportedOperationException("doFinal() is not supported");
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.macs.SipHash
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        this.m >>>= (7 - this.wordPos) << 3;
        this.m >>>= 8;
        this.m |= (((long) ((this.wordCount << 3) + this.wordPos)) & 255) << 56;
        processMessageWord();
        this.v2 ^= 238;
        applySipRounds(this.d);
        long r0 = ((this.v0 ^ this.v1) ^ this.v2) ^ this.v3;
        this.v1 ^= 221;
        applySipRounds(this.d);
        reset();
        Pack.longToLittleEndian(r0, out, outOff);
        Pack.longToLittleEndian(((this.v0 ^ this.v1) ^ this.v2) ^ this.v3, out, outOff + 8);
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac, com.mi.car.jsse.easysec.crypto.macs.SipHash
    public void reset() {
        super.reset();
        this.v1 ^= 238;
    }
}
