package com.mi.car.jsse.easysec.util.encoders;

import com.mi.car.jsse.easysec.util.Strings;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Base32 {
    private static final Encoder encoder = new Base32Encoder();

    public static String toBase32String(byte[] data) {
        return toBase32String(data, 0, data.length);
    }

    public static String toBase32String(byte[] data, int off, int length) {
        return Strings.fromByteArray(encode(data, off, length));
    }

    public static byte[] encode(byte[] data) {
        return encode(data, 0, data.length);
    }

    public static byte[] encode(byte[] data, int off, int length) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream(encoder.getEncodedLength(length));
        try {
            encoder.encode(data, off, length, bOut);
            return bOut.toByteArray();
        } catch (Exception e) {
            throw new EncoderException("exception encoding base32 string: " + e.getMessage(), e);
        }
    }

    public static int encode(byte[] data, OutputStream out) throws IOException {
        return encoder.encode(data, 0, data.length, out);
    }

    public static int encode(byte[] data, int off, int length, OutputStream out) throws IOException {
        return encoder.encode(data, off, length, out);
    }

    public static byte[] decode(byte[] data) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream((data.length / 8) * 5);
        try {
            encoder.decode(data, 0, data.length, bOut);
            return bOut.toByteArray();
        } catch (Exception e) {
            throw new DecoderException("unable to decode base32 data: " + e.getMessage(), e);
        }
    }

    public static byte[] decode(String data) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream((data.length() / 8) * 5);
        try {
            encoder.decode(data, bOut);
            return bOut.toByteArray();
        } catch (Exception e) {
            throw new DecoderException("unable to decode base32 string: " + e.getMessage(), e);
        }
    }

    public static int decode(String data, OutputStream out) throws IOException {
        return encoder.decode(data, out);
    }

    public static int decode(byte[] base32Data, int start, int length, OutputStream out) {
        try {
            return encoder.decode(base32Data, start, length, out);
        } catch (Exception e) {
            throw new DecoderException("unable to decode base32 data: " + e.getMessage(), e);
        }
    }
}
