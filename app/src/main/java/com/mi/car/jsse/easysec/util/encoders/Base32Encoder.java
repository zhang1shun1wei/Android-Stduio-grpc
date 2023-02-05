package com.mi.car.jsse.easysec.util.encoders;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.io.OutputStream;

public class Base32Encoder implements Encoder {
    private static final byte[] DEAULT_ENCODING_TABLE = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 50, 51, 52, 53, 54, 55};
    private static final byte DEFAULT_PADDING = 61;
    private final byte[] decodingTable;
    private final byte[] encodingTable;
    private final byte padding;

    /* access modifiers changed from: protected */
    public void initialiseDecodingTable() {
        for (int i = 0; i < this.decodingTable.length; i++) {
            this.decodingTable[i] = -1;
        }
        for (int i2 = 0; i2 < this.encodingTable.length; i2++) {
            this.decodingTable[this.encodingTable[i2]] = (byte) i2;
        }
    }

    public Base32Encoder() {
        this.decodingTable = new byte[128];
        this.encodingTable = DEAULT_ENCODING_TABLE;
        this.padding = DEFAULT_PADDING;
        initialiseDecodingTable();
    }

    public Base32Encoder(byte[] encodingTable2, byte padding2) {
        this.decodingTable = new byte[128];
        if (encodingTable2.length != 32) {
            throw new IllegalArgumentException("encoding table needs to be length 32");
        }
        this.encodingTable = Arrays.clone(encodingTable2);
        this.padding = padding2;
        initialiseDecodingTable();
    }

    public int encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) throws IOException {
        int inPos = inOff;
        int inEnd = (inOff + inLen) - 4;
        int outPos = outOff;
        while (inPos < inEnd) {
            encodeBlock(inBuf, inPos, outBuf, outPos);
            inPos += 5;
            outPos += 8;
        }
        int extra = inLen - (inPos - inOff);
        if (extra > 0) {
            byte[] in = new byte[5];
            System.arraycopy(inBuf, inPos, in, 0, extra);
            encodeBlock(in, 0, outBuf, outPos);
            switch (extra) {
                case 1:
                    outBuf[outPos + 2] = this.padding;
                    outBuf[outPos + 3] = this.padding;
                    outBuf[outPos + 4] = this.padding;
                    outBuf[outPos + 5] = this.padding;
                    outBuf[outPos + 6] = this.padding;
                    outBuf[outPos + 7] = this.padding;
                    break;
                case 2:
                    outBuf[outPos + 4] = this.padding;
                    outBuf[outPos + 5] = this.padding;
                    outBuf[outPos + 6] = this.padding;
                    outBuf[outPos + 7] = this.padding;
                    break;
                case 3:
                    outBuf[outPos + 5] = this.padding;
                    outBuf[outPos + 6] = this.padding;
                    outBuf[outPos + 7] = this.padding;
                    break;
                case 4:
                    outBuf[outPos + 7] = this.padding;
                    break;
            }
            outPos += 8;
        }
        return outPos - outOff;
    }

    private void encodeBlock(byte[] inBuf, int inPos, byte[] outBuf, int outPos) {
        int inPos2 = inPos + 1;
        byte b = inBuf[inPos];
        int inPos3 = inPos2 + 1;
        int a2 = inBuf[inPos2] & 255;
        int inPos4 = inPos3 + 1;
        int a3 = inBuf[inPos3] & 255;
        int a4 = inBuf[inPos4] & 255;
        int a5 = inBuf[inPos4 + 1] & 255;
        int outPos2 = outPos + 1;
        outBuf[outPos] = this.encodingTable[(b >>> 3) & 31];
        int outPos3 = outPos2 + 1;
        outBuf[outPos2] = this.encodingTable[((b << 2) | (a2 >>> 6)) & 31];
        int outPos4 = outPos3 + 1;
        outBuf[outPos3] = this.encodingTable[(a2 >>> 1) & 31];
        int outPos5 = outPos4 + 1;
        outBuf[outPos4] = this.encodingTable[((a2 << 4) | (a3 >>> 4)) & 31];
        int outPos6 = outPos5 + 1;
        outBuf[outPos5] = this.encodingTable[((a3 << 1) | (a4 >>> 7)) & 31];
        int outPos7 = outPos6 + 1;
        outBuf[outPos6] = this.encodingTable[(a4 >>> 2) & 31];
        outBuf[outPos7] = this.encodingTable[((a4 << 3) | (a5 >>> 5)) & 31];
        outBuf[outPos7 + 1] = this.encodingTable[a5 & 31];
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int getEncodedLength(int inputLength) {
        return ((inputLength + 4) / 5) * 8;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int getMaxDecodedLength(int inputLength) {
        return (inputLength / 8) * 5;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int encode(byte[] buf, int off, int len, OutputStream out) throws IOException {
        if (len < 0) {
            return 0;
        }
        byte[] tmp = new byte[72];
        int remaining = len;
        while (remaining > 0) {
            int inLen = Math.min(45, remaining);
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
        byte[] outBuffer = new byte[55];
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
        while (finish > off && i != 8) {
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
            byte b4 = this.decodingTable[data[i5]];
            int i6 = nextI(data, i5 + 1, finish);
            byte b5 = this.decodingTable[data[i6]];
            int i7 = nextI(data, i6 + 1, finish);
            byte b6 = this.decodingTable[data[i7]];
            int i8 = nextI(data, i7 + 1, finish);
            byte b7 = this.decodingTable[data[i8]];
            int i9 = nextI(data, i8 + 1, finish);
            int i10 = i9 + 1;
            byte b8 = this.decodingTable[data[i9]];
            if ((b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8) < 0) {
                throw new IOException("invalid characters encountered in base32 data");
            }
            int bufOff2 = bufOff + 1;
            outBuffer[bufOff] = (byte) ((b1 << 3) | (b2 >> 2));
            int bufOff3 = bufOff2 + 1;
            outBuffer[bufOff2] = (byte) ((b2 << 6) | (b3 << 1) | (b4 >> 4));
            int bufOff4 = bufOff3 + 1;
            outBuffer[bufOff3] = (byte) ((b4 << 4) | (b5 >> 1));
            int bufOff5 = bufOff4 + 1;
            outBuffer[bufOff4] = (byte) ((b5 << 7) | (b6 << 2) | (b7 >> 3));
            bufOff = bufOff5 + 1;
            outBuffer[bufOff5] = (byte) ((b7 << 5) | b8);
            if (bufOff == outBuffer.length) {
                out.write(outBuffer);
                bufOff = 0;
            }
            outLen += 5;
            i2 = nextI(data, i10, finish);
        }
        if (bufOff > 0) {
            out.write(outBuffer, 0, bufOff);
        }
        int e0 = nextI(data, i2, end);
        int e1 = nextI(data, e0 + 1, end);
        int e2 = nextI(data, e1 + 1, end);
        int e3 = nextI(data, e2 + 1, end);
        int e4 = nextI(data, e3 + 1, end);
        int e5 = nextI(data, e4 + 1, end);
        int e6 = nextI(data, e5 + 1, end);
        return outLen + decodeLastBlock(out, (char) data[e0], (char) data[e1], (char) data[e2], (char) data[e3], (char) data[e4], (char) data[e5], (char) data[e6], (char) data[nextI(data, e6 + 1, end)]);
    }

    private int nextI(byte[] data, int i, int finish) {
        while (i < finish && ignore((char) data[i])) {
            i++;
        }
        return i;
    }

    @Override // com.mi.car.jsse.easysec.util.encoders.Encoder
    public int decode(String data, OutputStream out) throws IOException {
        byte[] bytes = Strings.toByteArray(data);
        return decode(bytes, 0, bytes.length, out);
    }

    private int decodeLastBlock(OutputStream out, char c1, char c2, char c3, char c4, char c5, char c6, char c7, char c8) throws IOException {
        if (c8 != this.padding) {
            byte b1 = this.decodingTable[c1];
            byte b2 = this.decodingTable[c2];
            byte b3 = this.decodingTable[c3];
            byte b4 = this.decodingTable[c4];
            byte b5 = this.decodingTable[c5];
            byte b6 = this.decodingTable[c6];
            byte b7 = this.decodingTable[c7];
            byte b8 = this.decodingTable[c8];
            if ((b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8) < 0) {
                throw new IOException("invalid characters encountered at end of base32 data");
            }
            out.write((b1 << 3) | (b2 >> 2));
            out.write((b2 << 6) | (b3 << 1) | (b4 >> 4));
            out.write((b4 << 4) | (b5 >> 1));
            out.write((b5 << 7) | (b6 << 2) | (b7 >> 3));
            out.write((b7 << 5) | b8);
            return 5;
        } else if (c7 != this.padding) {
            byte b12 = this.decodingTable[c1];
            byte b22 = this.decodingTable[c2];
            byte b32 = this.decodingTable[c3];
            byte b42 = this.decodingTable[c4];
            byte b52 = this.decodingTable[c5];
            byte b62 = this.decodingTable[c6];
            byte b72 = this.decodingTable[c7];
            if ((b12 | b22 | b32 | b42 | b52 | b62 | b72) < 0) {
                throw new IOException("invalid characters encountered at end of base32 data");
            }
            out.write((b12 << 3) | (b22 >> 2));
            out.write((b22 << 6) | (b32 << 1) | (b42 >> 4));
            out.write((b42 << 4) | (b52 >> 1));
            out.write((b52 << 7) | (b62 << 2) | (b72 >> 3));
            return 4;
        } else if (c6 != this.padding) {
            throw new IOException("invalid characters encountered at end of base32 data");
        } else if (c5 != this.padding) {
            byte b13 = this.decodingTable[c1];
            byte b23 = this.decodingTable[c2];
            byte b33 = this.decodingTable[c3];
            byte b43 = this.decodingTable[c4];
            byte b53 = this.decodingTable[c5];
            if ((b13 | b23 | b33 | b43 | b53) < 0) {
                throw new IOException("invalid characters encountered at end of base32 data");
            }
            out.write((b13 << 3) | (b23 >> 2));
            out.write((b23 << 6) | (b33 << 1) | (b43 >> 4));
            out.write((b43 << 4) | (b53 >> 1));
            return 3;
        } else if (c4 != this.padding) {
            byte b14 = this.decodingTable[c1];
            byte b24 = this.decodingTable[c2];
            byte b34 = this.decodingTable[c3];
            byte b44 = this.decodingTable[c4];
            if ((b14 | b24 | b34 | b44) < 0) {
                throw new IOException("invalid characters encountered at end of base32 data");
            }
            out.write((b14 << 3) | (b24 >> 2));
            out.write((b24 << 6) | (b34 << 1) | (b44 >> 4));
            return 2;
        } else if (c3 != this.padding) {
            throw new IOException("invalid characters encountered at end of base32 data");
        } else {
            byte b15 = this.decodingTable[c1];
            byte b25 = this.decodingTable[c2];
            if ((b15 | b25) < 0) {
                throw new IOException("invalid characters encountered at end of base32 data");
            }
            out.write((b15 << 3) | (b25 >> 2));
            return 1;
        }
    }
}
