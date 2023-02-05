package com.mi.car.jsse.easysec.crypto.paddings;

import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import java.security.SecureRandom;

public class X923Padding implements BlockCipherPadding {
    SecureRandom random = null;

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public void init(SecureRandom random2) throws IllegalArgumentException {
        this.random = random2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public String getPaddingName() {
        return "X9.23";
    }

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public int addPadding(byte[] in, int inOff) {
        byte code = (byte) (in.length - inOff);
        while (inOff < in.length - 1) {
            if (this.random == null) {
                in[inOff] = 0;
            } else {
                in[inOff] = (byte) this.random.nextInt();
            }
            inOff++;
        }
        in[inOff] = code;
        return code;
    }

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public int padCount(byte[] in) throws InvalidCipherTextException {
        int count = in[in.length - 1] & 255;
        if (count <= in.length) {
            return count;
        }
        throw new InvalidCipherTextException("pad block corrupted");
    }
}
