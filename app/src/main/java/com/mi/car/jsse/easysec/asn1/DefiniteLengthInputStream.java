package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/* access modifiers changed from: package-private */
public class DefiniteLengthInputStream extends LimitedInputStream {
    private static final byte[] EMPTY_BYTES = new byte[0];
    private final int _originalLength;
    private int _remaining;

    DefiniteLengthInputStream(InputStream in, int length, int limit) {
        super(in, limit);
        if (length <= 0) {
            if (length < 0) {
                throw new IllegalArgumentException("negative lengths not allowed");
            }
            setParentEofDetect(true);
        }
        this._originalLength = length;
        this._remaining = length;
    }

    /* access modifiers changed from: package-private */
    public int getRemaining() {
        return this._remaining;
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        if (this._remaining == 0) {
            return -1;
        }
        int b = this._in.read();
        if (b < 0) {
            throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining);
        }
        int i = this._remaining - 1;
        this._remaining = i;
        if (i != 0) {
            return b;
        }
        setParentEofDetect(true);
        return b;
    }

    @Override // java.io.InputStream
    public int read(byte[] buf, int off, int len) throws IOException {
        if (this._remaining == 0) {
            return -1;
        }
        int numRead = this._in.read(buf, off, Math.min(len, this._remaining));
        if (numRead < 0) {
            throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining);
        }
        int i = this._remaining - numRead;
        this._remaining = i;
        if (i != 0) {
            return numRead;
        }
        setParentEofDetect(true);
        return numRead;
    }

    /* access modifiers changed from: package-private */
    public void readAllIntoByteArray(byte[] buf) throws IOException {
        if (this._remaining != buf.length) {
            throw new IllegalArgumentException("buffer length not right for data");
        } else if (this._remaining != 0) {
            int limit = getLimit();
            if (this._remaining >= limit) {
                throw new IOException("corrupted stream - out of bounds length found: " + this._remaining + " >= " + limit);
            }
            int readFully = this._remaining - Streams.readFully(this._in, buf, 0, buf.length);
            this._remaining = readFully;
            if (readFully != 0) {
                throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining);
            }
            setParentEofDetect(true);
        }
    }

    /* access modifiers changed from: package-private */
    public byte[] toByteArray() throws IOException {
        if (this._remaining == 0) {
            return EMPTY_BYTES;
        }
        int limit = getLimit();
        if (this._remaining >= limit) {
            throw new IOException("corrupted stream - out of bounds length found: " + this._remaining + " >= " + limit);
        }
        byte[] bytes = new byte[this._remaining];
        int readFully = this._remaining - Streams.readFully(this._in, bytes, 0, bytes.length);
        this._remaining = readFully;
        if (readFully != 0) {
            throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining);
        }
        setParentEofDetect(true);
        return bytes;
    }
}
