package com.mi.car.jsse.easysec.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

public class HexEncoder implements Encoder {
    protected final byte[] decodingTable = new byte[128];
    protected final byte[] encodingTable = {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102};

    /* access modifiers changed from: protected */
    public void initialiseDecodingTable() {
        for (int i = 0; i < this.decodingTable.length; i++) {
            this.decodingTable[i] = -1;
        }
        for (int i2 = 0; i2 < this.encodingTable.length; i2++) {
            this.decodingTable[this.encodingTable[i2]] = (byte) i2;
        }
        this.decodingTable[65] = this.decodingTable[97];
        this.decodingTable[66] = this.decodingTable[98];
        this.decodingTable[67] = this.decodingTable[99];
        this.decodingTable[68] = this.decodingTable[100];
        this.decodingTable[69] = this.decodingTable[101];
        this.decodingTable[70] = this.decodingTable[102];
    }

    public HexEncoder() {
        initialiseDecodingTable();
    }

    public int encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) throws IOException {
        int inEnd = inOff + inLen;
        int outPos = outOff;
        for (int inPos = inOff; inPos < inEnd; inPos++) {
            int b = inBuf[inPos] & 255;
            int outPos2 = outPos + 1;
            outBuf[outPos] = this.encodingTable[b >>> 4];
            outPos = outPos2 + 1;
            outBuf[outPos2] = this.encodingTable[b & 15];
        }
        return outPos - outOff;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int getEncodedLength(int inputLength) {
        return inputLength * 2;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int getMaxDecodedLength(int inputLength) {
        return inputLength / 2;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int encode(byte[] buf, int off, int len, OutputStream out) throws IOException {
        if (len < 0) {
            return 0;
        }
        byte[] tmp = new byte[72];
        int remaining = len;
        while (remaining > 0) {
            int inLen = Math.min(36, remaining);
            out.write(tmp, 0, encode(buf, off, inLen, tmp, 0));
            off += inLen;
            remaining -= inLen;
        }
        return len * 2;
    }

    private static boolean ignore(char c) {
        return c == '\n' || c == '\r' || c == '\t' || c == ' ';
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int decode(byte[] data, int off, int length, OutputStream out) throws IOException {
        int outLen = 0;
        byte[] buf = new byte[36];
        int end = off + length;
        while (end > off && ignore((char) data[end - 1])) {
            end--;
        }
        int i = off;
        int bufOff = 0;
        while (i < end) {
            int i2 = i;
            while (i2 < end && ignore((char) data[i2])) {
                i2++;
            }
            byte b1 = this.decodingTable[data[i2]];
            int i3 = i2 + 1;
            while (i3 < end && ignore((char) data[i3])) {
                i3++;
            }
            i = i3 + 1;
            byte b2 = this.decodingTable[data[i3]];
            if ((b1 | b2) < 0) {
                throw new IOException("invalid characters encountered in Hex data");
            }
            int bufOff2 = bufOff + 1;
            buf[bufOff] = (byte) ((b1 << 4) | b2);
            if (bufOff2 == buf.length) {
                out.write(buf);
                bufOff2 = 0;
            }
            outLen++;
            bufOff = bufOff2;
        }
        if (bufOff > 0) {
            out.write(buf, 0, bufOff);
        }
        return outLen;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int decode(String data, OutputStream out) throws IOException {
        int length = 0;
        byte[] buf = new byte[36];
        int end = data.length();
        while (end > 0 && ignore(data.charAt(end - 1))) {
            end--;
        }
        int i = 0;
        int bufOff = 0;
        while (i < end) {
            int i2 = i;
            while (i2 < end && ignore(data.charAt(i2))) {
                i2++;
            }
            byte b1 = this.decodingTable[data.charAt(i2)];
            int i3 = i2 + 1;
            while (i3 < end && ignore(data.charAt(i3))) {
                i3++;
            }
            i = i3 + 1;
            byte b2 = this.decodingTable[data.charAt(i3)];
            if ((b1 | b2) < 0) {
                throw new IOException("invalid characters encountered in Hex string");
            }
            int bufOff2 = bufOff + 1;
            buf[bufOff] = (byte) ((b1 << 4) | b2);
            if (bufOff2 == buf.length) {
                out.write(buf);
                bufOff2 = 0;
            }
            length++;
            bufOff = bufOff2;
        }
        if (bufOff > 0) {
            out.write(buf, 0, bufOff);
        }
        return length;
    }

    /* access modifiers changed from: package-private */
    public byte[] decodeStrict(String str, int off, int len) throws IOException {
        if (str == null) {
            throw new NullPointerException("'str' cannot be null");
        } else if (off < 0 || len < 0 || off > str.length() - len) {
            throw new IndexOutOfBoundsException("invalid offset and/or length specified");
        } else if ((len & 1) != 0) {
            throw new IOException("a hexadecimal encoding must have an even number of characters");
        } else {
            int resultLen = len >>> 1;
            byte[] result = new byte[resultLen];
            int strPos = off;
            for (int i = 0; i < resultLen; i++) {
                int strPos2 = strPos + 1;
                byte b1 = this.decodingTable[str.charAt(strPos)];
                strPos = strPos2 + 1;
                int n = (b1 << 4) | this.decodingTable[str.charAt(strPos2)];
                if (n < 0) {
                    throw new IOException("invalid characters encountered in Hex string");
                }
                result[i] = (byte) n;
            }
            return result;
        }
    }
}
