package com.mi.car.jsse.easysec.crypto.paddings;

import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.security.SecureRandom;

public class TBCPadding implements BlockCipherPadding {
    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public void init(SecureRandom random) throws IllegalArgumentException {
    }

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public String getPaddingName() {
        return "TBC";
    }

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public int addPadding(byte[] in, int inOff) {
        byte code;
        int i = GF2Field.MASK;
        int count = in.length - inOff;
        if (inOff > 0) {
            if ((in[inOff - 1] & 1) != 0) {
                i = 0;
            }
            code = (byte) i;
        } else {
            if ((in[in.length - 1] & 1) != 0) {
                i = 0;
            }
            code = (byte) i;
        }
        while (inOff < in.length) {
            in[inOff] = code;
            inOff++;
        }
        return count;
    }

    @Override // com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding
    public int padCount(byte[] in) throws InvalidCipherTextException {
        byte code = in[in.length - 1];
        int index = in.length - 1;
        while (index > 0 && in[index - 1] == code) {
            index--;
        }
        return in.length - index;
    }
}
