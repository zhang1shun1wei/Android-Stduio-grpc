package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.InputStream;

/* access modifiers changed from: package-private */
public class ConstructedBitStream extends InputStream {
    private ASN1BitStringParser _currentParser;
    private InputStream _currentStream;
    private boolean _first = true;
    private final boolean _octetAligned;
    private int _padBits = 0;
    private final ASN1StreamParser _parser;

    ConstructedBitStream(ASN1StreamParser parser, boolean octetAligned) {
        this._parser = parser;
        this._octetAligned = octetAligned;
    }

    /* access modifiers changed from: package-private */
    public int getPadBits() {
        return this._padBits;
    }

    @Override // java.io.InputStream
    public int read(byte[] b, int off, int len) throws IOException {
        if (this._currentStream == null) {
            if (!this._first) {
                return -1;
            }
            this._currentParser = getNextParser();
            if (this._currentParser == null) {
                return -1;
            }
            this._first = false;
            this._currentStream = this._currentParser.getBitStream();
        }
        int totalRead = 0;
        while (true) {
            int numRead = this._currentStream.read(b, off + totalRead, len - totalRead);
            if (numRead >= 0) {
                totalRead += numRead;
                if (totalRead == len) {
                    return totalRead;
                }
            } else {
                this._padBits = this._currentParser.getPadBits();
                this._currentParser = getNextParser();
                if (this._currentParser == null) {
                    this._currentStream = null;
                    if (totalRead < 1) {
                        totalRead = -1;
                    }
                    return totalRead;
                }
                this._currentStream = this._currentParser.getBitStream();
            }
        }
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        if (this._currentStream == null) {
            if (!this._first) {
                return -1;
            }
            this._currentParser = getNextParser();
            if (this._currentParser == null) {
                return -1;
            }
            this._first = false;
            this._currentStream = this._currentParser.getBitStream();
        }
        while (true) {
            int b = this._currentStream.read();
            if (b >= 0) {
                return b;
            }
            this._padBits = this._currentParser.getPadBits();
            this._currentParser = getNextParser();
            if (this._currentParser == null) {
                this._currentStream = null;
                return -1;
            }
            this._currentStream = this._currentParser.getBitStream();
        }
    }

    private ASN1BitStringParser getNextParser() throws IOException {
        ASN1Encodable asn1Obj = this._parser.readObject();
        if (asn1Obj == null) {
            if (!this._octetAligned || this._padBits == 0) {
                return null;
            }
            throw new IOException("expected octet-aligned bitstring, but found padBits: " + this._padBits);
        } else if (!(asn1Obj instanceof ASN1BitStringParser)) {
            throw new IOException("unknown object encountered: " + asn1Obj.getClass());
        } else if (this._padBits == 0) {
            return (ASN1BitStringParser) asn1Obj;
        } else {
            throw new IOException("only the last nested bitstring can have padding");
        }
    }
}
