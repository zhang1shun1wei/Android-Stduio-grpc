package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.MacDerivationFunction;
import com.mi.car.jsse.easysec.crypto.params.KDFCounterParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import java.math.BigInteger;

public class KDFCounterBytesGenerator implements MacDerivationFunction {
    private static final BigInteger INTEGER_MAX = BigInteger.valueOf(2147483647L);
    private static final BigInteger TWO = BigInteger.valueOf(2L);
    private final Mac prf;
    private final int h;
    private byte[] fixedInputDataCtrPrefix;
    private byte[] fixedInputData_afterCtr;
    private int maxSizeExcl;
    private byte[] ios;
    private int generatedBytes;
    private byte[] k;

    public KDFCounterBytesGenerator(Mac prf) {
        this.prf = prf;
        this.h = prf.getMacSize();
        this.k = new byte[this.h];
    }

    public void init(DerivationParameters param) {
        if (!(param instanceof KDFCounterParameters)) {
            throw new IllegalArgumentException("Wrong type of arguments given");
        } else {
            KDFCounterParameters kdfParams = (KDFCounterParameters)param;
            this.prf.init(new KeyParameter(kdfParams.getKI()));
            this.fixedInputDataCtrPrefix = kdfParams.getFixedInputDataCounterPrefix();
            this.fixedInputData_afterCtr = kdfParams.getFixedInputDataCounterSuffix();
            int r = kdfParams.getR();
            this.ios = new byte[r / 8];
            BigInteger maxSize = TWO.pow(r).multiply(BigInteger.valueOf((long)this.h));
            this.maxSizeExcl = maxSize.compareTo(INTEGER_MAX) == 1 ? 2147483647 : maxSize.intValue();
            this.generatedBytes = 0;
        }
    }

    public Mac getMac() {
        return this.prf;
    }

    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        int generatedBytesAfter = this.generatedBytes + len;
        if (generatedBytesAfter >= 0 && generatedBytesAfter < this.maxSizeExcl) {
            if (this.generatedBytes % this.h == 0) {
                this.generateNext();
            }

            int posInK = this.generatedBytes % this.h;
            int leftInK = this.h - this.generatedBytes % this.h;
            int toCopy = Math.min(leftInK, len);
            System.arraycopy(this.k, posInK, out, outOff, toCopy);
            this.generatedBytes += toCopy;
            int toGenerate = len - toCopy;

            for(outOff += toCopy; toGenerate > 0; outOff += toCopy) {
                this.generateNext();
                toCopy = Math.min(this.h, toGenerate);
                System.arraycopy(this.k, 0, out, outOff, toCopy);
                this.generatedBytes += toCopy;
                toGenerate -= toCopy;
            }

            return len;
        } else {
            throw new DataLengthException("Current KDFCTR may only be used for " + this.maxSizeExcl + " bytes");
        }
    }

    private void generateNext() {
        int i = this.generatedBytes / this.h + 1;
        switch(this.ios.length) {
            case 4:
                this.ios[0] = (byte)(i >>> 24);
            case 3:
                this.ios[this.ios.length - 3] = (byte)(i >>> 16);
            case 2:
                this.ios[this.ios.length - 2] = (byte)(i >>> 8);
            case 1:
                this.ios[this.ios.length - 1] = (byte)i;
                this.prf.update(this.fixedInputDataCtrPrefix, 0, this.fixedInputDataCtrPrefix.length);
                this.prf.update(this.ios, 0, this.ios.length);
                this.prf.update(this.fixedInputData_afterCtr, 0, this.fixedInputData_afterCtr.length);
                this.prf.doFinal(this.k, 0);
                return;
            default:
                throw new IllegalStateException("Unsupported size of counter i");
        }
    }
}