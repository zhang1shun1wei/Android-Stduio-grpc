package com.mi.car.jsse.easysec.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

public class Base64Encoder implements Encoder {
    protected final byte[] decodingTable = new byte[128];
    protected final byte[] encodingTable = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};
    protected byte padding = 61;

    /* access modifiers changed from: protected */
    public void initialiseDecodingTable() {
        for (int i = 0; i < this.decodingTable.length; i++) {
            this.decodingTable[i] = -1;
        }
        for (int i2 = 0; i2 < this.encodingTable.length; i2++) {
            this.decodingTable[this.encodingTable[i2]] = (byte) i2;
        }
    }

    public Base64Encoder() {
        initialiseDecodingTable();
    }

    public int encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) throws IOException {
        int outPos;
        int inEnd = (inOff + inLen) - 2;
        int outPos2 = outOff;
        int inPos = inOff;
        while (inPos < inEnd) {
            int inPos2 = inPos + 1;
            byte b = inBuf[inPos];
            int inPos3 = inPos2 + 1;
            int a2 = inBuf[inPos2] & 255;
            int a3 = inBuf[inPos3] & 255;
            int outPos3 = outPos2 + 1;
            outBuf[outPos2] = this.encodingTable[(b >>> 2) & 63];
            int outPos4 = outPos3 + 1;
            outBuf[outPos3] = this.encodingTable[((b << 4) | (a2 >>> 4)) & 63];
            int outPos5 = outPos4 + 1;
            outBuf[outPos4] = this.encodingTable[((a2 << 2) | (a3 >>> 6)) & 63];
            outPos2 = outPos5 + 1;
            outBuf[outPos5] = this.encodingTable[a3 & 63];
            inPos = inPos3 + 1;
        }
        switch (inLen - (inPos - inOff)) {
            case 1:
                int inPos4 = inPos + 1;
                int a1 = inBuf[inPos] & 255;
                int outPos6 = outPos2 + 1;
                outBuf[outPos2] = this.encodingTable[(a1 >>> 2) & 63];
                int outPos7 = outPos6 + 1;
                outBuf[outPos6] = this.encodingTable[(a1 << 4) & 63];
                int outPos8 = outPos7 + 1;
                outBuf[outPos7] = this.padding;
                outBuf[outPos8] = this.padding;
                outPos = outPos8 + 1;
                break;
            case 2:
                int inPos5 = inPos + 1;
                int a12 = inBuf[inPos] & 255;
                int i = inPos5 + 1;
                int a22 = inBuf[inPos5] & 255;
                int outPos9 = outPos2 + 1;
                outBuf[outPos2] = this.encodingTable[(a12 >>> 2) & 63];
                int outPos10 = outPos9 + 1;
                outBuf[outPos9] = this.encodingTable[((a12 << 4) | (a22 >>> 4)) & 63];
                int outPos11 = outPos10 + 1;
                outBuf[outPos10] = this.encodingTable[(a22 << 2) & 63];
                outBuf[outPos11] = this.padding;
                outPos = outPos11 + 1;
                break;
            default:
                outPos = outPos2;
                break;
        }
        return outPos - outOff;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int getEncodedLength(int inputLength) {
        return ((inputLength + 2) / 3) * 4;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int getMaxDecodedLength(int inputLength) {
        return (inputLength / 4) * 3;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int encode(byte[] buf, int off, int len, OutputStream out) throws IOException {
        if (len < 0) {
            return 0;
        }
        byte[] tmp = new byte[72];
        int remaining = len;
        while (remaining > 0) {
            int inLen = Math.min(54, remaining);
            out.write(tmp, 0, encode(buf, off, inLen, tmp, 0));
            off += inLen;
            remaining -= inLen;
        }
        return ((len + 2) / 3) * 4;
    }

    private boolean ignore(char c) {
        return c == '\n' || c == '\r' || c == '\t' || c == ' ';
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int decode(byte[] data, int off, int length, OutputStream out) throws IOException {
        byte[] outBuffer = new byte[54];
        int bufOff = 0;
        int outLen = 0;
        int end = off + length;
        while (end > off && ignore((char) data[end - 1])) {
            end--;
        }
        if (end == 0) {
            return 0;
        }
        int i = 0;
        int finish = end;
        while (finish > off && i != 4) {
            if (!ignore((char) data[finish - 1])) {
                i++;
            }
            finish--;
        }
        int i2 = nextI(data, off, finish);
        while (i2 < finish) {
            byte b1 = this.decodingTable[data[i2]];
            int i3 = nextI(data, i2 + 1, finish);
            byte b2 = this.decodingTable[data[i3]];
            int i4 = nextI(data, i3 + 1, finish);
            byte b3 = this.decodingTable[data[i4]];
            int i5 = nextI(data, i4 + 1, finish);
            int i6 = i5 + 1;
            byte b4 = this.decodingTable[data[i5]];
            if ((b1 | b2 | b3 | b4) < 0) {
                throw new IOException("invalid characters encountered in base64 data");
            }
            int bufOff2 = bufOff + 1;
            outBuffer[bufOff] = (byte) ((b1 << 2) | (b2 >> 4));
            int bufOff3 = bufOff2 + 1;
            outBuffer[bufOff2] = (byte) ((b2 << 4) | (b3 >> 2));
            bufOff = bufOff3 + 1;
            outBuffer[bufOff3] = (byte) ((b3 << 6) | b4);
            if (bufOff == outBuffer.length) {
                out.write(outBuffer);
                bufOff = 0;
            }
            outLen += 3;
            i2 = nextI(data, i6, finish);
        }
        if (bufOff > 0) {
            out.write(outBuffer, 0, bufOff);
        }
        int e0 = nextI(data, i2, end);
        int e1 = nextI(data, e0 + 1, end);
        int e2 = nextI(data, e1 + 1, end);
        return outLen + decodeLastBlock(out, (char) data[e0], (char) data[e1], (char) data[e2], (char) data[nextI(data, e2 + 1, end)]);
    }

    private int nextI(byte[] data, int i, int finish) {
        while (i < finish && ignore((char) data[i])) {
            i++;
        }
        return i;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int decode(String data, OutputStream out) throws IOException {
        byte[] outBuffer = new byte[54];
        int bufOff = 0;
        int length = 0;
        int end = data.length();
        while (end > 0 && ignore(data.charAt(end - 1))) {
            end--;
        }
        if (end == 0) {
            return 0;
        }
        int i = 0;
        int finish = end;
        while (finish > 0 && i != 4) {
            if (!ignore(data.charAt(finish - 1))) {
                i++;
            }
            finish--;
        }
        int i2 = nextI(data, 0, finish);
        while (i2 < finish) {
            byte b1 = this.decodingTable[data.charAt(i2)];
            int i3 = nextI(data, i2 + 1, finish);
            byte b2 = this.decodingTable[data.charAt(i3)];
            int i4 = nextI(data, i3 + 1, finish);
            byte b3 = this.decodingTable[data.charAt(i4)];
            int i5 = nextI(data, i4 + 1, finish);
            int i6 = i5 + 1;
            byte b4 = this.decodingTable[data.charAt(i5)];
            if ((b1 | b2 | b3 | b4) < 0) {
                throw new IOException("invalid characters encountered in base64 data");
            }
            int bufOff2 = bufOff + 1;
            outBuffer[bufOff] = (byte) ((b1 << 2) | (b2 >> 4));
            int bufOff3 = bufOff2 + 1;
            outBuffer[bufOff2] = (byte) ((b2 << 4) | (b3 >> 2));
            bufOff = bufOff3 + 1;
            outBuffer[bufOff3] = (byte) ((b3 << 6) | b4);
            length += 3;
            if (bufOff == outBuffer.length) {
                out.write(outBuffer);
                bufOff = 0;
            }
            i2 = nextI(data, i6, finish);
        }
        if (bufOff > 0) {
            out.write(outBuffer, 0, bufOff);
        }
        int e0 = nextI(data, i2, end);
        int e1 = nextI(data, e0 + 1, end);
        int e2 = nextI(data, e1 + 1, end);
        return length + decodeLastBlock(out, data.charAt(e0), data.charAt(e1), data.charAt(e2), data.charAt(nextI(data, e2 + 1, end)));
    }

    private int decodeLastBlock(OutputStream out, char c1, char c2, char c3, char c4) throws IOException {
        if (c3 == this.padding) {
            if (c4 != this.padding) {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            byte b1 = this.decodingTable[c1];
            byte b2 = this.decodingTable[c2];
            if ((b1 | b2) < 0) {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            out.write((b1 << 2) | (b2 >> 4));
            return 1;
        } else if (c4 == this.padding) {
            byte b12 = this.decodingTable[c1];
            byte b22 = this.decodingTable[c2];
            byte b3 = this.decodingTable[c3];
            if ((b12 | b22 | b3) < 0) {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            out.write((b12 << 2) | (b22 >> 4));
            out.write((b22 << 4) | (b3 >> 2));
            return 2;
        } else {
            byte b13 = this.decodingTable[c1];
            byte b23 = this.decodingTable[c2];
            byte b32 = this.decodingTable[c3];
            byte b4 = this.decodingTable[c4];
            if ((b13 | b23 | b32 | b4) < 0) {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            out.write((b13 << 2) | (b23 >> 4));
            out.write((b23 << 4) | (b32 >> 2));
            out.write((b32 << 6) | b4);
            return 3;
        }
    }

    private int nextI(String data, int i, int finish) {
        while (i < finish && ignore(data.charAt(i))) {
            i++;
        }
        return i;
    }
}
