//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.bsi.BSIObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.eac.EACObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSASSAPSSparams;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.tls.Certificate.ParseOptions;
import com.mi.car.jsse.easysec.tls.OfferedPsks.BindersConfig;
import com.mi.car.jsse.easysec.tls.OfferedPsks.SelectedConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.tls.crypto.TlsHashOutputStream;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Shorts;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class TlsUtils {
    private static byte[] DOWNGRADE_TLS11 = Hex.decodeStrict("444F574E47524400");
    private static byte[] DOWNGRADE_TLS12 = Hex.decodeStrict("444F574E47524401");
    private static final Hashtable CERT_SIG_ALG_OIDS = createCertSigAlgOIDs();
    private static final Vector DEFAULT_SUPPORTED_SIG_ALGS = createDefaultSupportedSigAlgs();
    public static final byte[] EMPTY_BYTES = new byte[0];
    public static final short[] EMPTY_SHORTS = new short[0];
    public static final int[] EMPTY_INTS = new int[0];
    public static final long[] EMPTY_LONGS = new long[0];
    public static final String[] EMPTY_STRINGS = new String[0];
    static final short MINIMUM_HASH_STRICT = 2;
    static final short MINIMUM_HASH_PREFERRED = 4;

    public TlsUtils() {
    }

    private static void addCertSigAlgOID(Hashtable h, ASN1ObjectIdentifier oid, SignatureAndHashAlgorithm sigAndHash) {
        h.put(oid.getId(), sigAndHash);
    }

    private static void addCertSigAlgOID(Hashtable h, ASN1ObjectIdentifier oid, short hashAlgorithm, short signatureAlgorithm) {
        addCertSigAlgOID(h, oid, SignatureAndHashAlgorithm.getInstance(hashAlgorithm, signatureAlgorithm));
    }

    private static Hashtable createCertSigAlgOIDs() {
        Hashtable h = new Hashtable();
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha224, (short)3, (short)2);
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha256, (short)4, (short)2);
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha384, (short)5, (short)2);
        addCertSigAlgOID(h, NISTObjectIdentifiers.dsa_with_sha512, (short)6, (short)2);
        addCertSigAlgOID(h, OIWObjectIdentifiers.dsaWithSHA1, (short)2, (short)2);
        addCertSigAlgOID(h, OIWObjectIdentifiers.sha1WithRSA, (short)2, (short)1);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha1WithRSAEncryption, (short)2, (short)1);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha224WithRSAEncryption, (short)3, (short)1);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha256WithRSAEncryption, (short)4, (short)1);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha384WithRSAEncryption, (short)5, (short)1);
        addCertSigAlgOID(h, PKCSObjectIdentifiers.sha512WithRSAEncryption, (short)6, (short)1);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA1, (short)2, (short)3);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA224, (short)3, (short)3);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA256, (short)4, (short)3);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA384, (short)5, (short)3);
        addCertSigAlgOID(h, X9ObjectIdentifiers.ecdsa_with_SHA512, (short)6, (short)3);
        addCertSigAlgOID(h, X9ObjectIdentifiers.id_dsa_with_sha1, (short)2, (short)2);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_1, (short)2, (short)3);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_224, (short)3, (short)3);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_256, (short)4, (short)3);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_384, (short)5, (short)3);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_ECDSA_SHA_512, (short)6, (short)3);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, (short)2, (short)1);
        addCertSigAlgOID(h, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, (short)4, (short)1);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA1, (short)2, (short)3);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA224, (short)3, (short)3);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA256, (short)4, (short)3);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA384, (short)5, (short)3);
        addCertSigAlgOID(h, BSIObjectIdentifiers.ecdsa_plain_SHA512, (short)6, (short)3);
        addCertSigAlgOID(h, EdECObjectIdentifiers.id_Ed25519, SignatureAndHashAlgorithm.ed25519);
        addCertSigAlgOID(h, EdECObjectIdentifiers.id_Ed448, SignatureAndHashAlgorithm.ed448);
        addCertSigAlgOID(h, RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, SignatureAndHashAlgorithm.gostr34102012_256);
        addCertSigAlgOID(h, RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, SignatureAndHashAlgorithm.gostr34102012_512);
        return h;
    }

    private static Vector createDefaultSupportedSigAlgs() {
        Vector result = new Vector();
        result.addElement(SignatureAndHashAlgorithm.ed25519);
        result.addElement(SignatureAndHashAlgorithm.ed448);
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)4, (short)3));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)5, (short)3));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)6, (short)3));
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
        result.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)4, (short)1));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)5, (short)1));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)6, (short)1));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)4, (short)2));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)5, (short)2));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)6, (short)2));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)3, (short)3));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)3, (short)1));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)3, (short)2));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)2, (short)3));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)2, (short)1));
        result.addElement(SignatureAndHashAlgorithm.getInstance((short)2, (short)2));
        return result;
    }

    public static void checkUint8(short i) throws IOException {
        if (!isValidUint8(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint8(int i) throws IOException {
        if (!isValidUint8(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint8(long i) throws IOException {
        if (!isValidUint8(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint16(int i) throws IOException {
        if (!isValidUint16(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint16(long i) throws IOException {
        if (!isValidUint16(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint24(int i) throws IOException {
        if (!isValidUint24(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint24(long i) throws IOException {
        if (!isValidUint24(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint32(long i) throws IOException {
        if (!isValidUint32(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint48(long i) throws IOException {
        if (!isValidUint48(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkUint64(long i) throws IOException {
        if (!isValidUint64(i)) {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static boolean isValidUint8(short i) {
        return (i & 255) == i;
    }

    public static boolean isValidUint8(int i) {
        return (i & 255) == i;
    }

    public static boolean isValidUint8(long i) {
        return (i & 255L) == i;
    }

    public static boolean isValidUint16(int i) {
        return (i & '\uffff') == i;
    }

    public static boolean isValidUint16(long i) {
        return (i & 65535L) == i;
    }

    public static boolean isValidUint24(int i) {
        return (i & 16777215) == i;
    }

    public static boolean isValidUint24(long i) {
        return (i & 16777215L) == i;
    }

    public static boolean isValidUint32(long i) {
        return (i & 4294967295L) == i;
    }

    public static boolean isValidUint48(long i) {
        return (i & 281474976710655L) == i;
    }

    public static boolean isValidUint64(long i) {
        return true;
    }

    public static boolean isSSL(TlsContext context) {
        return context.getServerVersion().isSSL();
    }

    public static boolean isTLSv10(ProtocolVersion version) {
        return ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv10(TlsContext context) {
        return isTLSv10(context.getServerVersion());
    }

    public static boolean isTLSv11(ProtocolVersion version) {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsContext context) {
        return isTLSv11(context.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion version) {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsContext context) {
        return isTLSv12(context.getServerVersion());
    }

    public static boolean isTLSv13(ProtocolVersion version) {
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv13(TlsContext context) {
        return isTLSv13(context.getServerVersion());
    }

    public static void writeUint8(short i, OutputStream output) throws IOException {
        output.write(i);
    }

    public static void writeUint8(int i, OutputStream output) throws IOException {
        output.write(i);
    }

    public static void writeUint8(short i, byte[] buf, int offset) {
        buf[offset] = (byte)i;
    }

    public static void writeUint8(int i, byte[] buf, int offset) {
        buf[offset] = (byte)i;
    }

    public static void writeUint16(int i, OutputStream output) throws IOException {
        output.write(i >>> 8);
        output.write(i);
    }

    public static void writeUint16(int i, byte[] buf, int offset) {
        buf[offset] = (byte)(i >>> 8);
        buf[offset + 1] = (byte)i;
    }

    public static void writeUint24(int i, OutputStream output) throws IOException {
        output.write((byte)(i >>> 16));
        output.write((byte)(i >>> 8));
        output.write((byte)i);
    }

    public static void writeUint24(int i, byte[] buf, int offset) {
        buf[offset] = (byte)(i >>> 16);
        buf[offset + 1] = (byte)(i >>> 8);
        buf[offset + 2] = (byte)i;
    }

    public static void writeUint32(long i, OutputStream output) throws IOException {
        output.write((byte)((int)(i >>> 24)));
        output.write((byte)((int)(i >>> 16)));
        output.write((byte)((int)(i >>> 8)));
        output.write((byte)((int)i));
    }

    public static void writeUint32(long i, byte[] buf, int offset) {
        buf[offset] = (byte)((int)(i >>> 24));
        buf[offset + 1] = (byte)((int)(i >>> 16));
        buf[offset + 2] = (byte)((int)(i >>> 8));
        buf[offset + 3] = (byte)((int)i);
    }

    public static void writeUint48(long i, OutputStream output) throws IOException {
        output.write((byte)((int)(i >>> 40)));
        output.write((byte)((int)(i >>> 32)));
        output.write((byte)((int)(i >>> 24)));
        output.write((byte)((int)(i >>> 16)));
        output.write((byte)((int)(i >>> 8)));
        output.write((byte)((int)i));
    }

    public static void writeUint48(long i, byte[] buf, int offset) {
        buf[offset] = (byte)((int)(i >>> 40));
        buf[offset + 1] = (byte)((int)(i >>> 32));
        buf[offset + 2] = (byte)((int)(i >>> 24));
        buf[offset + 3] = (byte)((int)(i >>> 16));
        buf[offset + 4] = (byte)((int)(i >>> 8));
        buf[offset + 5] = (byte)((int)i);
    }

    public static void writeUint64(long i, OutputStream output) throws IOException {
        output.write((byte)((int)(i >>> 56)));
        output.write((byte)((int)(i >>> 48)));
        output.write((byte)((int)(i >>> 40)));
        output.write((byte)((int)(i >>> 32)));
        output.write((byte)((int)(i >>> 24)));
        output.write((byte)((int)(i >>> 16)));
        output.write((byte)((int)(i >>> 8)));
        output.write((byte)((int)i));
    }

    public static void writeUint64(long i, byte[] buf, int offset) {
        buf[offset] = (byte)((int)(i >>> 56));
        buf[offset + 1] = (byte)((int)(i >>> 48));
        buf[offset + 2] = (byte)((int)(i >>> 40));
        buf[offset + 3] = (byte)((int)(i >>> 32));
        buf[offset + 4] = (byte)((int)(i >>> 24));
        buf[offset + 5] = (byte)((int)(i >>> 16));
        buf[offset + 6] = (byte)((int)(i >>> 8));
        buf[offset + 7] = (byte)((int)i);
    }

    public static void writeOpaque8(byte[] buf, OutputStream output) throws IOException {
        checkUint8(buf.length);
        writeUint8(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque8(byte[] data, byte[] buf, int off) throws IOException {
        checkUint8(data.length);
        writeUint8(data.length, buf, off);
        System.arraycopy(data, 0, buf, off + 1, data.length);
    }

    public static void writeOpaque16(byte[] buf, OutputStream output) throws IOException {
        checkUint16(buf.length);
        writeUint16(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque16(byte[] data, byte[] buf, int off) throws IOException {
        checkUint16(data.length);
        writeUint16(data.length, buf, off);
        System.arraycopy(data, 0, buf, off + 2, data.length);
    }

    public static void writeOpaque24(byte[] buf, OutputStream output) throws IOException {
        checkUint24(buf.length);
        writeUint24(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque24(byte[] data, byte[] buf, int off) throws IOException {
        checkUint24(data.length);
        writeUint24(data.length, buf, off);
        System.arraycopy(data, 0, buf, off + 3, data.length);
    }

    public static void writeUint8Array(short[] uints, OutputStream output) throws IOException {
        for(int i = 0; i < uints.length; ++i) {
            writeUint8(uints[i], output);
        }

    }

    public static void writeUint8Array(short[] uints, byte[] buf, int offset) throws IOException {
        for(int i = 0; i < uints.length; ++i) {
            writeUint8(uints[i], buf, offset);
            ++offset;
        }

    }

    public static void writeUint8ArrayWithUint8Length(short[] uints, OutputStream output) throws IOException {
        checkUint8(uints.length);
        writeUint8(uints.length, output);
        writeUint8Array(uints, output);
    }

    public static void writeUint8ArrayWithUint8Length(short[] uints, byte[] buf, int offset) throws IOException {
        checkUint8(uints.length);
        writeUint8(uints.length, buf, offset);
        writeUint8Array(uints, buf, offset + 1);
    }

    public static void writeUint16Array(int[] uints, OutputStream output) throws IOException {
        for(int i = 0; i < uints.length; ++i) {
            writeUint16(uints[i], output);
        }

    }

    public static void writeUint16Array(int[] uints, byte[] buf, int offset) throws IOException {
        for(int i = 0; i < uints.length; ++i) {
            writeUint16(uints[i], buf, offset);
            offset += 2;
        }

    }

    public static void writeUint16ArrayWithUint8Length(int[] uints, byte[] buf, int offset) throws IOException {
        int length = 2 * uints.length;
        checkUint8(length);
        writeUint8(length, buf, offset);
        writeUint16Array(uints, buf, offset + 1);
    }

    public static void writeUint16ArrayWithUint16Length(int[] uints, OutputStream output) throws IOException {
        int length = 2 * uints.length;
        checkUint16(length);
        writeUint16(length, output);
        writeUint16Array(uints, output);
    }

    public static void writeUint16ArrayWithUint16Length(int[] uints, byte[] buf, int offset) throws IOException {
        int length = 2 * uints.length;
        checkUint16(length);
        writeUint16(length, buf, offset);
        writeUint16Array(uints, buf, offset + 2);
    }

    public static byte[] decodeOpaque8(byte[] buf) throws IOException {
        return decodeOpaque8(buf, 0);
    }

    public static byte[] decodeOpaque8(byte[] buf, int minLength) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else if (buf.length < 1) {
            throw new TlsFatalAlert((short)50);
        } else {
            short length = readUint8(buf, 0);
            if (buf.length == length + 1 && length >= minLength) {
                return copyOfRangeExact(buf, 1, buf.length);
            } else {
                throw new TlsFatalAlert((short)50);
            }
        }
    }

    public static byte[] decodeOpaque16(byte[] buf) throws IOException {
        return decodeOpaque16(buf, 0);
    }

    public static byte[] decodeOpaque16(byte[] buf, int minLength) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else if (buf.length < 2) {
            throw new TlsFatalAlert((short)50);
        } else {
            int length = readUint16(buf, 0);
            if (buf.length == length + 2 && length >= minLength) {
                return copyOfRangeExact(buf, 2, buf.length);
            } else {
                throw new TlsFatalAlert((short)50);
            }
        }
    }

    public static short decodeUint8(byte[] buf) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else if (buf.length != 1) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readUint8(buf, 0);
        }
    }

    public static short[] decodeUint8ArrayWithUint8Length(byte[] buf) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else {
            int count = readUint8(buf, 0);
            if (buf.length != count + 1) {
                throw new TlsFatalAlert((short)50);
            } else {
                short[] uints = new short[count];

                for(int i = 0; i < count; ++i) {
                    uints[i] = readUint8(buf, i + 1);
                }

                return uints;
            }
        }
    }

    public static int decodeUint16(byte[] buf) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else if (buf.length != 2) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readUint16(buf, 0);
        }
    }

    public static int[] decodeUint16ArrayWithUint8Length(byte[] buf) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else {
            int length = readUint8(buf, 0);
            if (buf.length == length + 1 && (length & 1) == 0) {
                int count = length / 2;
                int pos = 1;
                int[] uints = new int[count];

                for(int i = 0; i < count; ++i) {
                    uints[i] = readUint16(buf, pos);
                    pos += 2;
                }

                return uints;
            } else {
                throw new TlsFatalAlert((short)50);
            }
        }
    }

    public static long decodeUint32(byte[] buf) throws IOException {
        if (buf == null) {
            throw new IllegalArgumentException("'buf' cannot be null");
        } else if (buf.length != 4) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readUint32(buf, 0);
        }
    }

    public static byte[] encodeOpaque8(byte[] buf) throws IOException {
        checkUint8(buf.length);
        return Arrays.prepend(buf, (byte)buf.length);
    }

    public static byte[] encodeOpaque16(byte[] buf) throws IOException {
        checkUint16(buf.length);
        byte[] r = new byte[2 + buf.length];
        writeUint16(buf.length, r, 0);
        System.arraycopy(buf, 0, r, 2, buf.length);
        return r;
    }

    public static byte[] encodeOpaque24(byte[] buf) throws IOException {
        checkUint24(buf.length);
        byte[] r = new byte[3 + buf.length];
        writeUint24(buf.length, r, 0);
        System.arraycopy(buf, 0, r, 3, buf.length);
        return r;
    }

    public static byte[] encodeUint8(short uint) throws IOException {
        checkUint8(uint);
        byte[] encoding = new byte[1];
        writeUint8((short)uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeUint8ArrayWithUint8Length(short[] uints) throws IOException {
        byte[] result = new byte[1 + uints.length];
        writeUint8ArrayWithUint8Length(uints, result, 0);
        return result;
    }

    public static byte[] encodeUint16(int uint) throws IOException {
        checkUint16(uint);
        byte[] encoding = new byte[2];
        writeUint16(uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeUint16ArrayWithUint8Length(int[] uints) throws IOException {
        int length = 2 * uints.length;
        byte[] result = new byte[1 + length];
        writeUint16ArrayWithUint8Length(uints, result, 0);
        return result;
    }

    public static byte[] encodeUint16ArrayWithUint16Length(int[] uints) throws IOException {
        int length = 2 * uints.length;
        byte[] result = new byte[2 + length];
        writeUint16ArrayWithUint16Length(uints, result, 0);
        return result;
    }

    public static byte[] encodeUint24(int uint) throws IOException {
        checkUint24(uint);
        byte[] encoding = new byte[3];
        writeUint24(uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeUint32(long uint) throws IOException {
        checkUint32(uint);
        byte[] encoding = new byte[4];
        writeUint32(uint, encoding, 0);
        return encoding;
    }

    public static byte[] encodeVersion(ProtocolVersion version) throws IOException {
        return new byte[]{(byte)version.getMajorVersion(), (byte)version.getMinorVersion()};
    }

    public static int readInt32(byte[] buf, int offset) {
        int n = buf[offset] << 24;
        ++offset;
        n |= (buf[offset] & 255) << 16;
        ++offset;
        n |= (buf[offset] & 255) << 8;
        ++offset;
        n |= buf[offset] & 255;
        return n;
    }

    public static short readUint8(InputStream input) throws IOException {
        int i = input.read();
        if (i < 0) {
            throw new EOFException();
        } else {
            return (short)i;
        }
    }

    public static short readUint8(byte[] buf, int offset) {
        return (short)(buf[offset] & 255);
    }

    public static int readUint16(InputStream input) throws IOException {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0) {
            throw new EOFException();
        } else {
            return i1 << 8 | i2;
        }
    }

    public static int readUint16(byte[] buf, int offset) {
        int n = (buf[offset] & 255) << 8;
        ++offset;
        n |= buf[offset] & 255;
        return n;
    }

    public static int readUint24(InputStream input) throws IOException {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        if (i3 < 0) {
            throw new EOFException();
        } else {
            return i1 << 16 | i2 << 8 | i3;
        }
    }

    public static int readUint24(byte[] buf, int offset) {
        int n = (buf[offset] & 255) << 16;
        ++offset;
        n |= (buf[offset] & 255) << 8;
        ++offset;
        n |= buf[offset] & 255;
        return n;
    }

    public static long readUint32(InputStream input) throws IOException {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        int i4 = input.read();
        if (i4 < 0) {
            throw new EOFException();
        } else {
            return (long)(i1 << 24 | i2 << 16 | i3 << 8 | i4) & 4294967295L;
        }
    }

    public static long readUint32(byte[] buf, int offset) {
        int n = (buf[offset] & 255) << 24;
        ++offset;
        n |= (buf[offset] & 255) << 16;
        ++offset;
        n |= (buf[offset] & 255) << 8;
        ++offset;
        n |= buf[offset] & 255;
        return (long)n & 4294967295L;
    }

    public static long readUint48(InputStream input) throws IOException {
        int hi = readUint24(input);
        int lo = readUint24(input);
        return ((long)hi & 4294967295L) << 24 | (long)lo & 4294967295L;
    }

    public static long readUint48(byte[] buf, int offset) {
        int hi = readUint24(buf, offset);
        int lo = readUint24(buf, offset + 3);
        return ((long)hi & 4294967295L) << 24 | (long)lo & 4294967295L;
    }

    public static byte[] readAllOrNothing(int length, InputStream input) throws IOException {
        if (length < 1) {
            return EMPTY_BYTES;
        } else {
            byte[] buf = new byte[length];
            int read = Streams.readFully(input, buf);
            if (read == 0) {
                return null;
            } else if (read != length) {
                throw new EOFException();
            } else {
                return buf;
            }
        }
    }

    public static byte[] readFully(int length, InputStream input) throws IOException {
        if (length < 1) {
            return EMPTY_BYTES;
        } else {
            byte[] buf = new byte[length];
            if (length != Streams.readFully(input, buf)) {
                throw new EOFException();
            } else {
                return buf;
            }
        }
    }

    public static void readFully(byte[] buf, InputStream input) throws IOException {
        int length = buf.length;
        if (length > 0 && length != Streams.readFully(input, buf)) {
            throw new EOFException();
        }
    }

    public static byte[] readOpaque8(InputStream input) throws IOException {
        short length = readUint8(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque8(InputStream input, int minLength) throws IOException {
        short length = readUint8(input);
        if (length < minLength) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readFully(length, input);
        }
    }

    public static byte[] readOpaque8(InputStream input, int minLength, int maxLength) throws IOException {
        short length = readUint8(input);
        if (length >= minLength && maxLength >= length) {
            return readFully(length, input);
        } else {
            throw new TlsFatalAlert((short)50);
        }
    }

    public static byte[] readOpaque16(InputStream input) throws IOException {
        int length = readUint16(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque16(InputStream input, int minLength) throws IOException {
        int length = readUint16(input);
        if (length < minLength) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readFully(length, input);
        }
    }

    public static byte[] readOpaque24(InputStream input) throws IOException {
        int length = readUint24(input);
        return readFully(length, input);
    }

    public static byte[] readOpaque24(InputStream input, int minLength) throws IOException {
        int length = readUint24(input);
        if (length < minLength) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readFully(length, input);
        }
    }

    public static short[] readUint8Array(int count, InputStream input) throws IOException {
        short[] uints = new short[count];

        for(int i = 0; i < count; ++i) {
            uints[i] = readUint8(input);
        }

        return uints;
    }

    public static short[] readUint8ArrayWithUint8Length(InputStream input, int minLength) throws IOException {
        int length = readUint8(input);
        if (length < minLength) {
            throw new TlsFatalAlert((short)50);
        } else {
            return readUint8Array(length, input);
        }
    }

    public static int[] readUint16Array(int count, InputStream input) throws IOException {
        int[] uints = new int[count];

        for(int i = 0; i < count; ++i) {
            uints[i] = readUint16(input);
        }

        return uints;
    }

    public static ProtocolVersion readVersion(byte[] buf, int offset) {
        return ProtocolVersion.get(buf[offset] & 255, buf[offset + 1] & 255);
    }

    public static ProtocolVersion readVersion(InputStream input) throws IOException {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0) {
            throw new EOFException();
        } else {
            return ProtocolVersion.get(i1, i2);
        }
    }

    public static ASN1Primitive readASN1Object(byte[] encoding) throws IOException {
        ASN1InputStream asn1 = new ASN1InputStream(encoding);
        ASN1Primitive result = asn1.readObject();
        if (null == result) {
            throw new TlsFatalAlert((short)50);
        } else if (null != asn1.readObject()) {
            throw new TlsFatalAlert((short)50);
        } else {
            return result;
        }
    }

    /** @deprecated */
    public static ASN1Primitive readDERObject(byte[] encoding) throws IOException {
        ASN1Primitive result = readASN1Object(encoding);
        requireDEREncoding(result, encoding);
        return result;
    }

    public static void requireDEREncoding(ASN1Object asn1, byte[] encoding) throws IOException {
        byte[] check = asn1.getEncoded("DER");
        if (!Arrays.areEqual(check, encoding)) {
            throw new TlsFatalAlert((short)50);
        }
    }

    public static void writeGMTUnixTime(byte[] buf, int offset) {
        int t = (int)(System.currentTimeMillis() / 1000L);
        buf[offset] = (byte)(t >>> 24);
        buf[offset + 1] = (byte)(t >>> 16);
        buf[offset + 2] = (byte)(t >>> 8);
        buf[offset + 3] = (byte)t;
    }

    public static void writeVersion(ProtocolVersion version, OutputStream output) throws IOException {
        output.write(version.getMajorVersion());
        output.write(version.getMinorVersion());
    }

    public static void writeVersion(ProtocolVersion version, byte[] buf, int offset) {
        buf[offset] = (byte)version.getMajorVersion();
        buf[offset + 1] = (byte)version.getMinorVersion();
    }

    public static void addIfSupported(Vector supportedAlgs, TlsCrypto crypto, SignatureAndHashAlgorithm alg) {
        if (crypto.hasSignatureAndHashAlgorithm(alg)) {
            supportedAlgs.addElement(alg);
        }

    }

    public static void addIfSupported(Vector supportedGroups, TlsCrypto crypto, int namedGroup) {
        if (crypto.hasNamedGroup(namedGroup)) {
            supportedGroups.addElement(Integers.valueOf(namedGroup));
        }

    }

    public static void addIfSupported(Vector supportedGroups, TlsCrypto crypto, int[] namedGroups) {
        for(int i = 0; i < namedGroups.length; ++i) {
            addIfSupported(supportedGroups, crypto, namedGroups[i]);
        }

    }

    public static boolean addToSet(Vector s, int i) {
        boolean result = !s.contains(Integers.valueOf(i));
        if (result) {
            s.add(Integers.valueOf(i));
        }

        return result;
    }

    public static Vector getDefaultDSSSignatureAlgorithms() {
        return getDefaultSignatureAlgorithms((short)2);
    }

    public static Vector getDefaultECDSASignatureAlgorithms() {
        return getDefaultSignatureAlgorithms((short)3);
    }

    public static Vector getDefaultRSASignatureAlgorithms() {
        return getDefaultSignatureAlgorithms((short)1);
    }

    public static SignatureAndHashAlgorithm getDefaultSignatureAlgorithm(short signatureAlgorithm) {
        switch(signatureAlgorithm) {
            case 1:
            case 2:
            case 3:
                return SignatureAndHashAlgorithm.getInstance((short)2, signatureAlgorithm);
            default:
                return null;
        }
    }

    public static Vector getDefaultSignatureAlgorithms(short signatureAlgorithm) {
        SignatureAndHashAlgorithm sigAndHashAlg = getDefaultSignatureAlgorithm(signatureAlgorithm);
        return null == sigAndHashAlg ? new Vector() : vectorOfOne(sigAndHashAlg);
    }

    public static Vector getDefaultSupportedSignatureAlgorithms(TlsContext context) {
        TlsCrypto crypto = context.getCrypto();
        int count = DEFAULT_SUPPORTED_SIG_ALGS.size();
        Vector result = new Vector(count);

        for(int i = 0; i < count; ++i) {
            addIfSupported(result, crypto, (SignatureAndHashAlgorithm)DEFAULT_SUPPORTED_SIG_ALGS.elementAt(i));
        }

        return result;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(TlsContext context, TlsCredentialedSigner signerCredentials) throws IOException {
        return getSignatureAndHashAlgorithm(context.getServerVersion(), signerCredentials);
    }

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(ProtocolVersion negotiatedVersion, TlsCredentialedSigner signerCredentials) throws IOException {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (isTLSv12(negotiatedVersion)) {
            signatureAndHashAlgorithm = signerCredentials.getSignatureAndHashAlgorithm();
            if (signatureAndHashAlgorithm == null) {
                throw new TlsFatalAlert((short)80);
            }
        }

        return signatureAndHashAlgorithm;
    }

    public static byte[] getExtensionData(Hashtable extensions, Integer extensionType) {
        return extensions == null ? null : (byte[])((byte[])extensions.get(extensionType));
    }

    public static boolean hasExpectedEmptyExtensionData(Hashtable extensions, Integer extensionType, short alertDescription) throws IOException {
        byte[] extension_data = getExtensionData(extensions, extensionType);
        if (extension_data == null) {
            return false;
        } else if (extension_data.length != 0) {
            throw new TlsFatalAlert(alertDescription);
        } else {
            return true;
        }
    }

    public static TlsSession importSession(byte[] sessionID, SessionParameters sessionParameters) {
        return new TlsSessionImpl(sessionID, sessionParameters);
    }

    static boolean isExtendedMasterSecretOptionalDTLS(ProtocolVersion[] activeProtocolVersions) {
        return ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.DTLSv12) || ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.DTLSv10);
    }

    static boolean isExtendedMasterSecretOptionalTLS(ProtocolVersion[] activeProtocolVersions) {
        return ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv12) || ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv11) || ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv10);
    }

    public static boolean isNullOrContainsNull(Object[] array) {
        if (null == array) {
            return true;
        } else {
            int count = array.length;

            for(int i = 0; i < count; ++i) {
                if (null == array[i]) {
                    return true;
                }
            }

            return false;
        }
    }

    public static boolean isNullOrEmpty(byte[] array) {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(short[] array) {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(int[] array) {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(Object[] array) {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(String s) {
        return null == s || s.length() < 1;
    }

    public static boolean isNullOrEmpty(Vector v) {
        return null == v || v.isEmpty();
    }

    public static boolean isSignatureAlgorithmsExtensionAllowed(ProtocolVersion version) {
        return null != version && ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static short getLegacyClientCertType(short signatureAlgorithm) {
        switch(signatureAlgorithm) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 64;
            default:
                return -1;
        }
    }

    public static short getLegacySignatureAlgorithmClient(short clientCertificateType) {
        switch(clientCertificateType) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 64:
                return 3;
            default:
                return -1;
        }
    }

    public static short getLegacySignatureAlgorithmClientCert(short clientCertificateType) {
        switch(clientCertificateType) {
            case 1:
            case 3:
            case 65:
                return 1;
            case 2:
            case 4:
                return 2;
            case 64:
            case 66:
                return 3;
            default:
                return -1;
        }
    }

    public static short getLegacySignatureAlgorithmServer(int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 3:
            case 22:
                return 2;
            case 5:
            case 19:
            case 23:
                return 1;
            case 17:
                return 3;
            default:
                return -1;
        }
    }

    public static short getLegacySignatureAlgorithmServerCert(int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 1:
            case 5:
            case 9:
            case 15:
            case 18:
            case 19:
            case 23:
                return 1;
            case 2:
            case 4:
            case 6:
            case 8:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 20:
            case 21:
            default:
                return -1;
            case 3:
            case 7:
            case 22:
                return 2;
            case 16:
            case 17:
                return 3;
        }
    }

    public static Vector getLegacySupportedSignatureAlgorithms() {
        Vector result = new Vector(3);
        result.add(SignatureAndHashAlgorithm.getInstance((short)2, (short)2));
        result.add(SignatureAndHashAlgorithm.getInstance((short)2, (short)3));
        result.add(SignatureAndHashAlgorithm.getInstance((short)2, (short)1));
        return result;
    }

    public static void encodeSupportedSignatureAlgorithms(Vector supportedSignatureAlgorithms, OutputStream output) throws IOException {
        if (supportedSignatureAlgorithms != null && supportedSignatureAlgorithms.size() >= 1 && supportedSignatureAlgorithms.size() < 32768) {
            int length = 2 * supportedSignatureAlgorithms.size();
            checkUint16(length);
            writeUint16(length, output);

            for(int i = 0; i < supportedSignatureAlgorithms.size(); ++i) {
                SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
                if (entry.getSignature() == 0) {
                    throw new IllegalArgumentException("SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension");
                }

                entry.encode(output);
            }

        } else {
            throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }
    }

    public static Vector parseSupportedSignatureAlgorithms(InputStream input) throws IOException {
        int length = readUint16(input);
        if (length >= 2 && (length & 1) == 0) {
            int count = length / 2;
            Vector supportedSignatureAlgorithms = new Vector(count);

            for(int i = 0; i < count; ++i) {
                SignatureAndHashAlgorithm sigAndHashAlg = SignatureAndHashAlgorithm.parse(input);
                if (0 != sigAndHashAlg.getSignature()) {
                    supportedSignatureAlgorithms.addElement(sigAndHashAlg);
                }
            }

            return supportedSignatureAlgorithms;
        } else {
            throw new TlsFatalAlert((short)50);
        }
    }

    public static void verifySupportedSignatureAlgorithm(Vector supportedSignatureAlgorithms, SignatureAndHashAlgorithm signatureAlgorithm) throws IOException {
        if (supportedSignatureAlgorithms != null && supportedSignatureAlgorithms.size() >= 1 && supportedSignatureAlgorithms.size() < 32768) {
            if (signatureAlgorithm == null) {
                throw new IllegalArgumentException("'signatureAlgorithm' cannot be null");
            } else if (signatureAlgorithm.getSignature() == 0 || !containsSignatureAlgorithm(supportedSignatureAlgorithms, signatureAlgorithm)) {
                throw new TlsFatalAlert((short)47);
            }
        } else {
            throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }
    }

    public static boolean containsSignatureAlgorithm(Vector supportedSignatureAlgorithms, SignatureAndHashAlgorithm signatureAlgorithm) throws IOException {
        for(int i = 0; i < supportedSignatureAlgorithms.size(); ++i) {
            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
            if (entry.equals(signatureAlgorithm)) {
                return true;
            }
        }

        return false;
    }

    public static boolean containsAnySignatureAlgorithm(Vector supportedSignatureAlgorithms, short signatureAlgorithm) {
        for(int i = 0; i < supportedSignatureAlgorithms.size(); ++i) {
            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
            if (entry.getSignature() == signatureAlgorithm) {
                return true;
            }
        }

        return false;
    }

    public static TlsSecret PRF(SecurityParameters securityParameters, TlsSecret secret, String asciiLabel, byte[] seed, int length) {
        try {
            return secret.deriveUsingPRF(securityParameters.getPRFAlgorithm(), asciiLabel, seed, length);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /** @deprecated */
    public static TlsSecret PRF(TlsContext context, TlsSecret secret, String asciiLabel, byte[] seed, int length) {
        return PRF(context.getSecurityParametersHandshake(), secret, asciiLabel, seed, length);
    }

    public static byte[] clone(byte[] data) {
        return null == data ? (byte[])null : (data.length == 0 ? EMPTY_BYTES : (byte[])((byte[])data.clone()));
    }

    public static String[] clone(String[] s) {
        return null == s ? (String[])null : (s.length < 1 ? EMPTY_STRINGS : (String[])((String[])s.clone()));
    }

    public static boolean constantTimeAreEqual(int len, byte[] a, int aOff, byte[] b, int bOff) {
        int d = 0;

        for(int i = 0; i < len; ++i) {
            d |= a[aOff + i] ^ b[bOff + i];
        }

        return 0 == d;
    }

    public static byte[] copyOfRangeExact(byte[] original, int from, int to) {
        int newLength = to - from;
        byte[] copy = new byte[newLength];
        System.arraycopy(original, from, copy, 0, newLength);
        return copy;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static byte[] calculateEndPointHash(TlsContext context, TlsCertificate certificate, byte[] enc) throws IOException {
        return calculateEndPointHash(context, certificate, enc, 0, enc.length);
    }

    static byte[] calculateEndPointHash(TlsContext context, TlsCertificate certificate, byte[] enc, int encOff, int encLen) throws IOException {
        short hashAlgorithm = 0;
        String sigAlgOID = certificate.getSigAlgOID();
        if (sigAlgOID != null) {
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID)) {
                RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(certificate.getSigAlgParams());
                if (null != pssParams) {
                    ASN1ObjectIdentifier hashOID = pssParams.getHashAlgorithm().getAlgorithm();
                    if (NISTObjectIdentifiers.id_sha256.equals(hashOID)) {
                        hashAlgorithm = 4;
                    } else if (NISTObjectIdentifiers.id_sha384.equals(hashOID)) {
                        hashAlgorithm = 5;
                    } else if (NISTObjectIdentifiers.id_sha512.equals(hashOID)) {
                        hashAlgorithm = 6;
                    }
                }
            } else {
                SignatureAndHashAlgorithm sigAndHashAlg = (SignatureAndHashAlgorithm)CERT_SIG_ALG_OIDS.get(sigAlgOID);
                if (sigAndHashAlg != null) {
                    hashAlgorithm = sigAndHashAlg.getHash();
                }
            }
        }

        switch(hashAlgorithm) {
            case 1:
            case 2:
                hashAlgorithm = 4;
                break;
            case 8:
                hashAlgorithm = 0;
        }

        if (0 != hashAlgorithm) {
            TlsHash hash = createHash(context.getCrypto(), hashAlgorithm);
            if (hash != null) {
                hash.update(enc, encOff, encLen);
                return hash.calculateHash();
            }
        }

        return EMPTY_BYTES;
    }

    public static byte[] calculateExporterSeed(SecurityParameters securityParameters, byte[] context) {
        byte[] cr = securityParameters.getClientRandom();
        byte[] sr = securityParameters.getServerRandom();
        if (null == context) {
            return Arrays.concatenate(cr, sr);
        } else if (!isValidUint16(context.length)) {
            throw new IllegalArgumentException("'context' must have length less than 2^16 (or be null)");
        } else {
            byte[] contextLength = new byte[2];
            writeUint16(context.length, contextLength, 0);
            return Arrays.concatenate(cr, sr, contextLength, context);
        }
    }

    private static byte[] calculateFinishedHMAC(SecurityParameters securityParameters, TlsSecret baseKey, byte[] transcriptHash) throws IOException {
        int prfCryptoHashAlgorithm = securityParameters.getPRFCryptoHashAlgorithm();
        int prfHashLength = securityParameters.getPRFHashLength();
        return calculateFinishedHMAC(prfCryptoHashAlgorithm, prfHashLength, baseKey, transcriptHash);
    }

    private static byte[] calculateFinishedHMAC(int prfCryptoHashAlgorithm, int prfHashLength, TlsSecret baseKey, byte[] transcriptHash) throws IOException {
        TlsSecret finishedKey = TlsCryptoUtils.hkdfExpandLabel(baseKey, prfCryptoHashAlgorithm, "finished", EMPTY_BYTES, prfHashLength);

        byte[] var5;
        try {
            var5 = finishedKey.calculateHMAC(prfCryptoHashAlgorithm, transcriptHash, 0, transcriptHash.length);
        } finally {
            finishedKey.destroy();
        }

        return var5;
    }

    static TlsSecret calculateMasterSecret(TlsContext context, TlsSecret preMasterSecret) {
        SecurityParameters sp = context.getSecurityParametersHandshake();
        String asciiLabel;
        byte[] seed;
        if (sp.isExtendedMasterSecret()) {
            asciiLabel = "extended master secret";
            seed = sp.getSessionHash();
        } else {
            asciiLabel = "master secret";
            seed = concat(sp.getClientRandom(), sp.getServerRandom());
        }

        return PRF((SecurityParameters)sp, preMasterSecret, asciiLabel, seed, 48);
    }

    static byte[] calculatePSKBinder(TlsCrypto crypto, boolean isExternalPSK, int pskCryptoHashAlgorithm, TlsSecret earlySecret, byte[] transcriptHash) throws IOException {
        int prfHashLength = TlsCryptoUtils.getHashOutputSize(pskCryptoHashAlgorithm);
        String label = isExternalPSK ? "ext binder" : "res binder";
        byte[] emptyTranscriptHash = crypto.createHash(pskCryptoHashAlgorithm).calculateHash();
        TlsSecret binderKey = deriveSecret(pskCryptoHashAlgorithm, prfHashLength, earlySecret, label, emptyTranscriptHash);

        byte[] var9;
        try {
            var9 = calculateFinishedHMAC(pskCryptoHashAlgorithm, prfHashLength, binderKey, transcriptHash);
        } finally {
            binderKey.destroy();
        }

        return var9;
    }

    static byte[] calculateVerifyData(TlsContext context, TlsHandshakeHash handshakeHash, boolean isServer) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        byte[] prfHash;
        if (isTLSv13(negotiatedVersion)) {
            TlsSecret baseKey = isServer ? securityParameters.getBaseKeyServer() : securityParameters.getBaseKeyClient();
            prfHash = getCurrentPRFHash(handshakeHash);
            return calculateFinishedHMAC(securityParameters, baseKey, prfHash);
        } else if (negotiatedVersion.isSSL()) {
            return SSL3Utils.calculateVerifyData(handshakeHash, isServer);
        } else {
            String asciiLabel = isServer ? "server finished" : "client finished";
            prfHash = getCurrentPRFHash(handshakeHash);
            TlsSecret master_secret = securityParameters.getMasterSecret();
            int verify_data_length = securityParameters.getVerifyDataLength();
            return PRF(securityParameters, master_secret, asciiLabel, prfHash, verify_data_length).extract();
        }
    }

    static void establish13PhaseSecrets(TlsContext context, TlsSecret pskEarlySecret, TlsSecret sharedSecret) throws IOException {
        TlsCrypto crypto = context.getCrypto();
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        int cryptoHashAlgorithm = securityParameters.getPRFCryptoHashAlgorithm();
        TlsSecret zeros = crypto.hkdfInit(cryptoHashAlgorithm);
        byte[] emptyTranscriptHash = crypto.createHash(cryptoHashAlgorithm).calculateHash();
        TlsSecret earlySecret = pskEarlySecret;
        if (null == pskEarlySecret) {
            earlySecret = crypto.hkdfInit(cryptoHashAlgorithm).hkdfExtract(cryptoHashAlgorithm, zeros);
        }

        if (null == sharedSecret) {
            sharedSecret = zeros;
        }

        TlsSecret handshakeSecret = deriveSecret(securityParameters, earlySecret, "derived", emptyTranscriptHash).hkdfExtract(cryptoHashAlgorithm, sharedSecret);
        if (sharedSecret != zeros) {
            sharedSecret.destroy();
        }

        TlsSecret masterSecret = deriveSecret(securityParameters, handshakeSecret, "derived", emptyTranscriptHash).hkdfExtract(cryptoHashAlgorithm, zeros);
        securityParameters.earlySecret = earlySecret;
        securityParameters.handshakeSecret = handshakeSecret;
        securityParameters.masterSecret = masterSecret;
    }

    private static void establish13TrafficSecrets(TlsContext context, byte[] transcriptHash, TlsSecret phaseSecret, String clientLabel, String serverLabel, RecordStream recordStream) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        securityParameters.trafficSecretClient = deriveSecret(securityParameters, phaseSecret, clientLabel, transcriptHash);
        if (null != serverLabel) {
            securityParameters.trafficSecretServer = deriveSecret(securityParameters, phaseSecret, serverLabel, transcriptHash);
        }

        recordStream.setPendingCipher(initCipher(context));
    }

    static void establish13PhaseApplication(TlsContext context, byte[] serverFinishedTranscriptHash, RecordStream recordStream) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        TlsSecret phaseSecret = securityParameters.getMasterSecret();
        establish13TrafficSecrets(context, serverFinishedTranscriptHash, phaseSecret, "c ap traffic", "s ap traffic", recordStream);
        securityParameters.exporterMasterSecret = deriveSecret(securityParameters, phaseSecret, "exp master", serverFinishedTranscriptHash);
    }

    static void establish13PhaseEarly(TlsContext context, byte[] clientHelloTranscriptHash, RecordStream recordStream) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        TlsSecret phaseSecret = securityParameters.getEarlySecret();
        if (null != recordStream) {
            establish13TrafficSecrets(context, clientHelloTranscriptHash, phaseSecret, "c e traffic", (String)null, recordStream);
        }

        securityParameters.earlyExporterMasterSecret = deriveSecret(securityParameters, phaseSecret, "e exp master", clientHelloTranscriptHash);
    }

    static void establish13PhaseHandshake(TlsContext context, byte[] serverHelloTranscriptHash, RecordStream recordStream) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        TlsSecret phaseSecret = securityParameters.getHandshakeSecret();
        establish13TrafficSecrets(context, serverHelloTranscriptHash, phaseSecret, "c hs traffic", "s hs traffic", recordStream);
        securityParameters.baseKeyClient = securityParameters.getTrafficSecretClient();
        securityParameters.baseKeyServer = securityParameters.getTrafficSecretServer();
    }

    static void update13TrafficSecretLocal(TlsContext context) throws IOException {
        update13TrafficSecret(context, context.isServer());
    }

    static void update13TrafficSecretPeer(TlsContext context) throws IOException {
        update13TrafficSecret(context, !context.isServer());
    }

    private static void update13TrafficSecret(TlsContext context, boolean forServer) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersConnection();
        TlsSecret current;
        if (forServer) {
            current = securityParameters.getTrafficSecretServer();
            securityParameters.trafficSecretServer = update13TrafficSecret(securityParameters, current);
        } else {
            current = securityParameters.getTrafficSecretClient();
            securityParameters.trafficSecretClient = update13TrafficSecret(securityParameters, current);
        }

        if (null != current) {
            current.destroy();
        }

    }

    private static TlsSecret update13TrafficSecret(SecurityParameters securityParameters, TlsSecret secret) throws IOException {
        return TlsCryptoUtils.hkdfExpandLabel(secret, securityParameters.getPRFCryptoHashAlgorithm(), "traffic upd", EMPTY_BYTES, securityParameters.getPRFHashLength());
    }

    /** @deprecated */
    public static short getHashAlgorithmForPRFAlgorithm(int prfAlgorithm) {
        switch(prfAlgorithm) {
            case 0:
            case 1:
                throw new IllegalArgumentException("legacy PRF not a valid algorithm");
            case 2:
            case 4:
                return 4;
            case 3:
            case 5:
                return 5;
            default:
                throw new IllegalArgumentException("unknown PRFAlgorithm: " + PRFAlgorithm.getText(prfAlgorithm));
        }
    }

    public static ASN1ObjectIdentifier getOIDForHashAlgorithm(short hashAlgorithm) {
        switch(hashAlgorithm) {
            case 1:
                return PKCSObjectIdentifiers.md5;
            case 2:
                return X509ObjectIdentifiers.id_SHA1;
            case 3:
                return NISTObjectIdentifiers.id_sha224;
            case 4:
                return NISTObjectIdentifiers.id_sha256;
            case 5:
                return NISTObjectIdentifiers.id_sha384;
            case 6:
                return NISTObjectIdentifiers.id_sha512;
            default:
                throw new IllegalArgumentException("invalid HashAlgorithm: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    static int getPRFAlgorithm(SecurityParameters securityParameters, int cipherSuite) throws IOException {
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        boolean isTLSv13 = isTLSv13(negotiatedVersion);
        boolean isTLSv12Exactly = !isTLSv13 && isTLSv12(negotiatedVersion);
        boolean isSSL = negotiatedVersion.isSSL();
        switch(cipherSuite) {
            case 59:
            case 60:
            case 61:
            case 62:
            case 63:
            case 64:
            case 103:
            case 104:
            case 105:
            case 106:
            case 107:
            case 108:
            case 109:
            case 156:
            case 158:
            case 160:
            case 162:
            case 164:
            case 166:
            case 168:
            case 170:
            case 172:
            case 186:
            case 187:
            case 188:
            case 189:
            case 190:
            case 191:
            case 192:
            case 193:
            case 194:
            case 195:
            case 196:
            case 197:
            case 49187:
            case 49189:
            case 49191:
            case 49193:
            case 49195:
            case 49197:
            case 49199:
            case 49201:
            case 49212:
            case 49214:
            case 49216:
            case 49218:
            case 49220:
            case 49222:
            case 49224:
            case 49226:
            case 49228:
            case 49230:
            case 49232:
            case 49234:
            case 49236:
            case 49238:
            case 49240:
            case 49242:
            case 49244:
            case 49246:
            case 49248:
            case 49250:
            case 49252:
            case 49254:
            case 49256:
            case 49258:
            case 49260:
            case 49262:
            case 49264:
            case 49266:
            case 49268:
            case 49270:
            case 49272:
            case 49274:
            case 49276:
            case 49278:
            case 49280:
            case 49282:
            case 49284:
            case 49286:
            case 49288:
            case 49290:
            case 49292:
            case 49294:
            case 49296:
            case 49298:
            case 49308:
            case 49309:
            case 49310:
            case 49311:
            case 49312:
            case 49313:
            case 49314:
            case 49315:
            case 49316:
            case 49317:
            case 49318:
            case 49319:
            case 49320:
            case 49321:
            case 49322:
            case 49323:
            case 49324:
            case 49325:
            case 49326:
            case 49327:
            case 52392:
            case 52393:
            case 52394:
            case 52395:
            case 52396:
            case 52397:
            case 52398:
            case 53249:
            case 53251:
            case 53253:
                if (isTLSv12Exactly) {
                    return 2;
                }

                throw new TlsFatalAlert((short)47);
            case 157:
            case 159:
            case 161:
            case 163:
            case 165:
            case 167:
            case 169:
            case 171:
            case 173:
            case 49188:
            case 49190:
            case 49192:
            case 49194:
            case 49196:
            case 49198:
            case 49200:
            case 49202:
            case 49213:
            case 49215:
            case 49217:
            case 49219:
            case 49221:
            case 49223:
            case 49225:
            case 49227:
            case 49229:
            case 49231:
            case 49233:
            case 49235:
            case 49237:
            case 49239:
            case 49241:
            case 49243:
            case 49245:
            case 49247:
            case 49249:
            case 49251:
            case 49253:
            case 49255:
            case 49257:
            case 49259:
            case 49261:
            case 49263:
            case 49265:
            case 49267:
            case 49269:
            case 49271:
            case 49273:
            case 49275:
            case 49277:
            case 49279:
            case 49281:
            case 49283:
            case 49285:
            case 49287:
            case 49289:
            case 49291:
            case 49293:
            case 49295:
            case 49297:
            case 49299:
            case 53250:
                if (isTLSv12Exactly) {
                    return 3;
                }

                throw new TlsFatalAlert((short)47);
            case 175:
            case 177:
            case 179:
            case 181:
            case 183:
            case 185:
            case 49208:
            case 49211:
            case 49301:
            case 49303:
            case 49305:
            case 49307:
                if (isTLSv13) {
                    throw new TlsFatalAlert((short)47);
                } else if (isTLSv12Exactly) {
                    return 3;
                } else {
                    if (isSSL) {
                        return 0;
                    }

                    return 1;
                }
            case 198:
            case 199:
                if (isTLSv13) {
                    return 7;
                }

                throw new TlsFatalAlert((short)47);
            case 4865:
            case 4867:
            case 4868:
            case 4869:
                if (isTLSv13) {
                    return 4;
                }

                throw new TlsFatalAlert((short)47);
            case 4866:
                if (isTLSv13) {
                    return 5;
                }

                throw new TlsFatalAlert((short)47);
            default:
                if (isTLSv13) {
                    throw new TlsFatalAlert((short)47);
                } else if (isTLSv12Exactly) {
                    return 2;
                } else {
                    return isSSL ? 0 : 1;
                }
        }
    }

    static int getPRFAlgorithm13(int cipherSuite) {
        switch(cipherSuite) {
            case 198:
            case 199:
                return 7;
            case 4865:
            case 4867:
            case 4868:
            case 4869:
                return 4;
            case 4866:
                return 5;
            default:
                return -1;
        }
    }

    static int[] getPRFAlgorithms13(int[] cipherSuites) {
        int[] result = new int[Math.min(3, cipherSuites.length)];
        int count = 0;

        for(int i = 0; i < cipherSuites.length; ++i) {
            int prfAlgorithm = getPRFAlgorithm13(cipherSuites[i]);
            if (prfAlgorithm >= 0 && !Arrays.contains(result, prfAlgorithm)) {
                result[count++] = prfAlgorithm;
            }
        }

        return truncate(result, count);
    }

    static byte[] calculateSignatureHash(TlsContext context, SignatureAndHashAlgorithm algorithm, byte[] extraSignatureInput, DigestInputBuffer buf) {
        TlsCrypto crypto = context.getCrypto();
        TlsHash h = algorithm == null ? new CombinedHash(crypto) : createHash(crypto, algorithm.getHash());
        SecurityParameters sp = context.getSecurityParametersHandshake();
        byte[] randoms = Arrays.concatenate(sp.getClientRandom(), sp.getServerRandom());
        ((TlsHash)h).update(randoms, 0, randoms.length);
        if (null != extraSignatureInput) {
            ((TlsHash)h).update(extraSignatureInput, 0, extraSignatureInput.length);
        }

        buf.updateDigest((TlsHash)h);
        return ((TlsHash)h).calculateHash();
    }

    static void sendSignatureInput(TlsContext context, byte[] extraSignatureInput, DigestInputBuffer buf, OutputStream output) throws IOException {
        SecurityParameters sp = context.getSecurityParametersHandshake();
        byte[] randoms = Arrays.concatenate(sp.getClientRandom(), sp.getServerRandom());
        output.write(randoms);
        if (null != extraSignatureInput) {
            output.write(extraSignatureInput);
        }

        buf.copyInputTo(output);
        output.close();
    }

    static DigitallySigned generateCertificateVerifyClient(TlsClientContext clientContext, TlsCredentialedSigner credentialedSigner, TlsStreamSigner streamSigner, TlsHandshakeHash handshakeHash) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (isTLSv13(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = getSignatureAndHashAlgorithm(negotiatedVersion, credentialedSigner);
            byte[] signature;
            if (streamSigner != null) {
                handshakeHash.copyBufferTo(streamSigner.getOutputStream());
                signature = streamSigner.getSignature();
            } else {
                byte[] hash;
                if (signatureAndHashAlgorithm == null) {
                    hash = securityParameters.getSessionHash();
                } else {
                    int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                    int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
                    hash = handshakeHash.getFinalHash(cryptoHashAlgorithm);
                }

                signature = credentialedSigner.generateRawSignature(hash);
            }

            return new DigitallySigned(signatureAndHashAlgorithm, signature);
        }
    }

    static DigitallySigned generate13CertificateVerify(TlsContext context, TlsCredentialedSigner credentialedSigner, TlsHandshakeHash handshakeHash) throws IOException {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = credentialedSigner.getSignatureAndHashAlgorithm();
        if (null == signatureAndHashAlgorithm) {
            throw new TlsFatalAlert((short)80);
        } else {
            String contextString = context.isServer() ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify";
            byte[] signature = generate13CertificateVerify(context.getCrypto(), credentialedSigner, contextString, handshakeHash, signatureAndHashAlgorithm);
            return new DigitallySigned(signatureAndHashAlgorithm, signature);
        }
    }

    private static byte[] generate13CertificateVerify(TlsCrypto crypto, TlsCredentialedSigner credentialedSigner, String contextString, TlsHandshakeHash handshakeHash, SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        TlsStreamSigner streamSigner = credentialedSigner.getStreamSigner();
        byte[] header = getCertificateVerifyHeader(contextString);
        byte[] prfHash = getCurrentPRFHash(handshakeHash);
        if (null != streamSigner) {
            OutputStream output = streamSigner.getOutputStream();
            output.write(header, 0, header.length);
            output.write(prfHash, 0, prfHash.length);
            return streamSigner.getSignature();
        } else {
            int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            TlsHash tlsHash = crypto.createHash(cryptoHashAlgorithm);
            tlsHash.update(header, 0, header.length);
            tlsHash.update(prfHash, 0, prfHash.length);
            byte[] hash = tlsHash.calculateHash();
            return credentialedSigner.generateRawSignature(hash);
        }
    }

    static void verifyCertificateVerifyClient(TlsServerContext serverContext, CertificateRequest certificateRequest, DigitallySigned certificateVerify, TlsHandshakeHash handshakeHash) throws IOException {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        Certificate clientCertificate = securityParameters.getPeerCertificate();
        TlsCertificate verifyingCert = clientCertificate.getCertificateAt(0);
        SignatureAndHashAlgorithm sigAndHashAlg = certificateVerify.getAlgorithm();
        short signatureAlgorithm;
        if (null == sigAndHashAlg) {
            signatureAlgorithm = verifyingCert.getLegacySignatureAlgorithm();
            short clientCertType = getLegacyClientCertType(signatureAlgorithm);
            if (clientCertType < 0 || !Arrays.contains(certificateRequest.getCertificateTypes(), clientCertType)) {
                throw new TlsFatalAlert((short)43);
            }
        } else {
            signatureAlgorithm = sigAndHashAlg.getSignature();
            if (!isValidSignatureAlgorithmForCertificateVerify(signatureAlgorithm, certificateRequest.getCertificateTypes())) {
                throw new TlsFatalAlert((short)47);
            }

            verifySupportedSignatureAlgorithm(securityParameters.getServerSigAlgs(), sigAndHashAlg);
        }

        boolean verified;
        try {
            TlsVerifier verifier = verifyingCert.createVerifier(signatureAlgorithm);
            TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(certificateVerify);
            if (streamVerifier != null) {
                handshakeHash.copyBufferTo(streamVerifier.getOutputStream());
                verified = streamVerifier.isVerified();
            } else {
                byte[] hash;
                if (isTLSv12((TlsContext)serverContext)) {
                    int signatureScheme = SignatureScheme.from(sigAndHashAlg);
                    int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
                    hash = handshakeHash.getFinalHash(cryptoHashAlgorithm);
                } else {
                    hash = securityParameters.getSessionHash();
                }

                verified = verifier.verifyRawSignature(certificateVerify, hash);
            }
        } catch (TlsFatalAlert var15) {
            throw var15;
        } catch (Exception var16) {
            throw new TlsFatalAlert((short)51, var16);
        }

        if (!verified) {
            throw new TlsFatalAlert((short)51);
        }
    }

    static void verify13CertificateVerifyClient(TlsServerContext serverContext, CertificateRequest certificateRequest, DigitallySigned certificateVerify, TlsHandshakeHash handshakeHash) throws IOException {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        Certificate clientCertificate = securityParameters.getPeerCertificate();
        TlsCertificate verifyingCert = clientCertificate.getCertificateAt(0);
        SignatureAndHashAlgorithm sigAndHashAlg = certificateVerify.getAlgorithm();
        verifySupportedSignatureAlgorithm(securityParameters.getServerSigAlgs(), sigAndHashAlg);
        int signatureScheme = SignatureScheme.from(sigAndHashAlg);

        boolean verified;
        try {
            TlsVerifier verifier = verifyingCert.createVerifier(signatureScheme);
            verified = verify13CertificateVerify(serverContext.getCrypto(), certificateVerify, verifier, "TLS 1.3, client CertificateVerify", handshakeHash);
        } catch (TlsFatalAlert var11) {
            throw var11;
        } catch (Exception var12) {
            throw new TlsFatalAlert((short)51, var12);
        }

        if (!verified) {
            throw new TlsFatalAlert((short)51);
        }
    }

    static void verify13CertificateVerifyServer(TlsClientContext clientContext, DigitallySigned certificateVerify, TlsHandshakeHash handshakeHash) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        Certificate serverCertificate = securityParameters.getPeerCertificate();
        TlsCertificate verifyingCert = serverCertificate.getCertificateAt(0);
        SignatureAndHashAlgorithm sigAndHashAlg = certificateVerify.getAlgorithm();
        verifySupportedSignatureAlgorithm(securityParameters.getClientSigAlgs(), sigAndHashAlg);
        int signatureScheme = SignatureScheme.from(sigAndHashAlg);

        boolean verified;
        try {
            TlsVerifier verifier = verifyingCert.createVerifier(signatureScheme);
            verified = verify13CertificateVerify(clientContext.getCrypto(), certificateVerify, verifier, "TLS 1.3, server CertificateVerify", handshakeHash);
        } catch (TlsFatalAlert var10) {
            throw var10;
        } catch (Exception var11) {
            throw new TlsFatalAlert((short)51, var11);
        }

        if (!verified) {
            throw new TlsFatalAlert((short)51);
        }
    }

    private static boolean verify13CertificateVerify(TlsCrypto crypto, DigitallySigned certificateVerify, TlsVerifier verifier, String contextString, TlsHandshakeHash handshakeHash) throws IOException {
        TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(certificateVerify);
        byte[] header = getCertificateVerifyHeader(contextString);
        byte[] prfHash = getCurrentPRFHash(handshakeHash);
        if (null != streamVerifier) {
            OutputStream output = streamVerifier.getOutputStream();
            output.write(header, 0, header.length);
            output.write(prfHash, 0, prfHash.length);
            return streamVerifier.isVerified();
        } else {
            int signatureScheme = SignatureScheme.from(certificateVerify.getAlgorithm());
            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            TlsHash tlsHash = crypto.createHash(cryptoHashAlgorithm);
            tlsHash.update(header, 0, header.length);
            tlsHash.update(prfHash, 0, prfHash.length);
            byte[] hash = tlsHash.calculateHash();
            return verifier.verifyRawSignature(certificateVerify, hash);
        }
    }

    private static byte[] getCertificateVerifyHeader(String contextString) {
        int count = contextString.length();
        byte[] header = new byte[64 + count + 1];

        int i;
        for(i = 0; i < 64; ++i) {
            header[i] = 32;
        }

        for(i = 0; i < count; ++i) {
            char c = contextString.charAt(i);
            header[64 + i] = (byte)c;
        }

        header[64 + count] = 0;
        return header;
    }

    static void generateServerKeyExchangeSignature(TlsContext context, TlsCredentialedSigner credentials, byte[] extraSignatureInput, DigestInputBuffer digestBuffer) throws IOException {
        SignatureAndHashAlgorithm algorithm = getSignatureAndHashAlgorithm(context, credentials);
        TlsStreamSigner streamSigner = credentials.getStreamSigner();
        byte[] signature;
        if (streamSigner != null) {
            sendSignatureInput(context, extraSignatureInput, digestBuffer, streamSigner.getOutputStream());
            signature = streamSigner.getSignature();
        } else {
            byte[] hash = calculateSignatureHash(context, algorithm, extraSignatureInput, digestBuffer);
            signature = credentials.generateRawSignature(hash);
        }

        DigitallySigned digitallySigned = new DigitallySigned(algorithm, signature);
        digitallySigned.encode(digestBuffer);
    }

    static void verifyServerKeyExchangeSignature(TlsContext context, InputStream signatureInput, TlsCertificate serverCertificate, byte[] extraSignatureInput, DigestInputBuffer digestBuffer) throws IOException {
        DigitallySigned digitallySigned = DigitallySigned.parse(context, signatureInput);
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        int keyExchangeAlgorithm = securityParameters.getKeyExchangeAlgorithm();
        SignatureAndHashAlgorithm sigAndHashAlg = digitallySigned.getAlgorithm();
        short signatureAlgorithm;
        if (sigAndHashAlg == null) {
            signatureAlgorithm = getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);
        } else {
            signatureAlgorithm = sigAndHashAlg.getSignature();
            if (!isValidSignatureAlgorithmForServerKeyExchange(signatureAlgorithm, keyExchangeAlgorithm)) {
                throw new TlsFatalAlert((short)47);
            }

            verifySupportedSignatureAlgorithm(securityParameters.getClientSigAlgs(), sigAndHashAlg);
        }

        TlsVerifier verifier = serverCertificate.createVerifier(signatureAlgorithm);
        TlsStreamVerifier streamVerifier = verifier.getStreamVerifier(digitallySigned);
        boolean verified;
        if (streamVerifier != null) {
            sendSignatureInput(context, extraSignatureInput, digestBuffer, streamVerifier.getOutputStream());
            verified = streamVerifier.isVerified();
        } else {
            byte[] hash = calculateSignatureHash(context, sigAndHashAlg, extraSignatureInput, digestBuffer);
            verified = verifier.verifyRawSignature(digitallySigned, hash);
        }

        if (!verified) {
            throw new TlsFatalAlert((short)51);
        }
    }

    static void trackHashAlgorithms(TlsHandshakeHash handshakeHash, Vector supportedSignatureAlgorithms) {
        if (supportedSignatureAlgorithms != null) {
            for(int i = 0; i < supportedSignatureAlgorithms.size(); ++i) {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
                if (cryptoHashAlgorithm >= 0) {
                    handshakeHash.trackHashAlgorithm(cryptoHashAlgorithm);
                } else if (8 == signatureAndHashAlgorithm.getHash()) {
                    handshakeHash.forceBuffering();
                }
            }
        }

    }

    public static boolean hasSigningCapability(short clientCertificateType) {
        switch(clientCertificateType) {
            case 1:
            case 2:
            case 64:
                return true;
            default:
                return false;
        }
    }

    public static Vector vectorOfOne(Object obj) {
        Vector v = new Vector(1);
        v.addElement(obj);
        return v;
    }

    public static int getCipherType(int cipherSuite) {
        int encryptionAlgorithm = getEncryptionAlgorithm(cipherSuite);
        return getEncryptionAlgorithmType(encryptionAlgorithm);
    }

    public static int getEncryptionAlgorithm(int cipherSuite) {
        switch(cipherSuite) {
            case 2:
            case 44:
            case 45:
            case 46:
            case 49153:
            case 49158:
            case 49163:
            case 49168:
            case 49173:
            case 49209:
                return 0;
            case 10:
            case 13:
            case 16:
            case 19:
            case 22:
            case 27:
            case 139:
            case 143:
            case 147:
            case 49155:
            case 49160:
            case 49165:
            case 49170:
            case 49175:
            case 49178:
            case 49179:
            case 49180:
            case 49204:
                return 7;
            case 47:
            case 48:
            case 49:
            case 50:
            case 51:
            case 52:
            case 60:
            case 62:
            case 63:
            case 64:
            case 103:
            case 108:
            case 140:
            case 144:
            case 148:
            case 174:
            case 178:
            case 182:
            case 49156:
            case 49161:
            case 49166:
            case 49171:
            case 49176:
            case 49181:
            case 49182:
            case 49183:
            case 49187:
            case 49189:
            case 49191:
            case 49193:
            case 49205:
            case 49207:
                return 8;
            case 53:
            case 54:
            case 55:
            case 56:
            case 57:
            case 58:
            case 61:
            case 104:
            case 105:
            case 106:
            case 107:
            case 109:
            case 141:
            case 145:
            case 149:
            case 175:
            case 179:
            case 183:
            case 49157:
            case 49162:
            case 49167:
            case 49172:
            case 49177:
            case 49184:
            case 49185:
            case 49186:
            case 49188:
            case 49190:
            case 49192:
            case 49194:
            case 49206:
            case 49208:
                return 9;
            case 59:
            case 176:
            case 180:
            case 184:
            case 49210:
                return 0;
            case 65:
            case 66:
            case 67:
            case 68:
            case 69:
            case 70:
            case 186:
            case 187:
            case 188:
            case 189:
            case 190:
            case 191:
            case 49266:
            case 49268:
            case 49270:
            case 49272:
            case 49300:
            case 49302:
            case 49304:
            case 49306:
                return 12;
            case 132:
            case 133:
            case 134:
            case 135:
            case 136:
            case 137:
            case 192:
            case 193:
            case 194:
            case 195:
            case 196:
            case 197:
            case 49267:
            case 49269:
            case 49271:
            case 49273:
            case 49301:
            case 49303:
            case 49305:
            case 49307:
                return 13;
            case 150:
            case 151:
            case 152:
            case 153:
            case 154:
            case 155:
                return 14;
            case 156:
            case 158:
            case 160:
            case 162:
            case 164:
            case 166:
            case 168:
            case 170:
            case 172:
            case 4865:
            case 49195:
            case 49197:
            case 49199:
            case 49201:
            case 53249:
                return 10;
            case 157:
            case 159:
            case 161:
            case 163:
            case 165:
            case 167:
            case 169:
            case 171:
            case 173:
            case 4866:
            case 49196:
            case 49198:
            case 49200:
            case 49202:
            case 53250:
                return 11;
            case 177:
            case 181:
            case 185:
            case 49211:
                return 0;
            case 198:
                return 27;
            case 199:
                return 26;
            case 4867:
            case 52392:
            case 52393:
            case 52394:
            case 52395:
            case 52396:
            case 52397:
            case 52398:
                return 21;
            case 4868:
            case 49308:
            case 49310:
            case 49316:
            case 49318:
            case 49324:
            case 53253:
                return 15;
            case 4869:
            case 49312:
            case 49314:
            case 49320:
            case 49322:
            case 49326:
            case 53251:
                return 16;
            case 49212:
            case 49214:
            case 49216:
            case 49218:
            case 49220:
            case 49222:
            case 49224:
            case 49226:
            case 49228:
            case 49230:
            case 49252:
            case 49254:
            case 49256:
            case 49264:
                return 22;
            case 49213:
            case 49215:
            case 49217:
            case 49219:
            case 49221:
            case 49223:
            case 49225:
            case 49227:
            case 49229:
            case 49231:
            case 49253:
            case 49255:
            case 49257:
            case 49265:
                return 23;
            case 49232:
            case 49234:
            case 49236:
            case 49238:
            case 49240:
            case 49242:
            case 49244:
            case 49246:
            case 49248:
            case 49250:
            case 49258:
            case 49260:
            case 49262:
                return 24;
            case 49233:
            case 49235:
            case 49237:
            case 49239:
            case 49241:
            case 49243:
            case 49245:
            case 49247:
            case 49249:
            case 49251:
            case 49259:
            case 49261:
            case 49263:
                return 25;
            case 49274:
            case 49276:
            case 49278:
            case 49280:
            case 49282:
            case 49284:
            case 49286:
            case 49288:
            case 49290:
            case 49292:
            case 49294:
            case 49296:
            case 49298:
                return 19;
            case 49275:
            case 49277:
            case 49279:
            case 49281:
            case 49283:
            case 49285:
            case 49287:
            case 49289:
            case 49291:
            case 49293:
            case 49295:
            case 49297:
            case 49299:
                return 20;
            case 49309:
            case 49311:
            case 49317:
            case 49319:
            case 49325:
                return 17;
            case 49313:
            case 49315:
            case 49321:
            case 49323:
            case 49327:
                return 18;
            default:
                return -1;
        }
    }

    public static int getEncryptionAlgorithmType(int encryptionAlgorithm) {
        switch(encryptionAlgorithm) {
            case 0:
            case 1:
            case 2:
                return 0;
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 12:
            case 13:
            case 14:
            case 22:
            case 23:
            case 28:
                return 1;
            case 10:
            case 11:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 24:
            case 25:
            case 26:
            case 27:
                return 2;
            default:
                return -1;
        }
    }

    public static int getKeyExchangeAlgorithm(int cipherSuite) {
        switch(cipherSuite) {
            case 2:
            case 10:
            case 47:
            case 53:
            case 59:
            case 60:
            case 61:
            case 65:
            case 132:
            case 150:
            case 156:
            case 157:
            case 186:
            case 192:
            case 49212:
            case 49213:
            case 49232:
            case 49233:
            case 49274:
            case 49275:
            case 49308:
            case 49309:
            case 49312:
            case 49313:
                return 1;
            case 13:
            case 48:
            case 54:
            case 62:
            case 66:
            case 104:
            case 133:
            case 151:
            case 164:
            case 165:
            case 187:
            case 193:
            case 49214:
            case 49215:
            case 49240:
            case 49241:
            case 49282:
            case 49283:
                return 7;
            case 16:
            case 49:
            case 55:
            case 63:
            case 67:
            case 105:
            case 134:
            case 152:
            case 160:
            case 161:
            case 188:
            case 194:
            case 49216:
            case 49217:
            case 49236:
            case 49237:
            case 49278:
            case 49279:
                return 9;
            case 19:
            case 50:
            case 56:
            case 64:
            case 68:
            case 106:
            case 135:
            case 153:
            case 162:
            case 163:
            case 189:
            case 195:
            case 49218:
            case 49219:
            case 49238:
            case 49239:
            case 49280:
            case 49281:
                return 3;
            case 22:
            case 51:
            case 57:
            case 69:
            case 103:
            case 107:
            case 136:
            case 154:
            case 158:
            case 159:
            case 190:
            case 196:
            case 49220:
            case 49221:
            case 49234:
            case 49235:
            case 49276:
            case 49277:
            case 49310:
            case 49311:
            case 49314:
            case 49315:
            case 52394:
                return 5;
            case 27:
            case 52:
            case 58:
            case 70:
            case 108:
            case 109:
            case 137:
            case 155:
            case 166:
            case 167:
            case 191:
            case 197:
            case 49222:
            case 49223:
            case 49242:
            case 49243:
            case 49284:
            case 49285:
                return 11;
            case 44:
            case 139:
            case 140:
            case 141:
            case 168:
            case 169:
            case 174:
            case 175:
            case 176:
            case 177:
            case 49252:
            case 49253:
            case 49258:
            case 49259:
            case 49294:
            case 49295:
            case 49300:
            case 49301:
            case 49316:
            case 49317:
            case 49320:
            case 49321:
            case 52395:
                return 13;
            case 45:
            case 143:
            case 144:
            case 145:
            case 170:
            case 171:
            case 178:
            case 179:
            case 180:
            case 181:
            case 49254:
            case 49255:
            case 49260:
            case 49261:
            case 49296:
            case 49297:
            case 49302:
            case 49303:
            case 49318:
            case 49319:
            case 49322:
            case 49323:
            case 52397:
                return 14;
            case 46:
            case 147:
            case 148:
            case 149:
            case 172:
            case 173:
            case 182:
            case 183:
            case 184:
            case 185:
            case 49256:
            case 49257:
            case 49262:
            case 49263:
            case 49298:
            case 49299:
            case 49304:
            case 49305:
            case 52398:
                return 15;
            case 198:
            case 199:
            case 4865:
            case 4866:
            case 4867:
            case 4868:
            case 4869:
                return 0;
            case 49153:
            case 49155:
            case 49156:
            case 49157:
            case 49189:
            case 49190:
            case 49197:
            case 49198:
            case 49226:
            case 49227:
            case 49246:
            case 49247:
            case 49268:
            case 49269:
            case 49288:
            case 49289:
                return 16;
            case 49158:
            case 49160:
            case 49161:
            case 49162:
            case 49187:
            case 49188:
            case 49195:
            case 49196:
            case 49224:
            case 49225:
            case 49244:
            case 49245:
            case 49266:
            case 49267:
            case 49286:
            case 49287:
            case 49324:
            case 49325:
            case 49326:
            case 49327:
            case 52393:
                return 17;
            case 49163:
            case 49165:
            case 49166:
            case 49167:
            case 49193:
            case 49194:
            case 49201:
            case 49202:
            case 49230:
            case 49231:
            case 49250:
            case 49251:
            case 49272:
            case 49273:
            case 49292:
            case 49293:
                return 18;
            case 49168:
            case 49170:
            case 49171:
            case 49172:
            case 49191:
            case 49192:
            case 49199:
            case 49200:
            case 49228:
            case 49229:
            case 49248:
            case 49249:
            case 49270:
            case 49271:
            case 49290:
            case 49291:
            case 52392:
                return 19;
            case 49173:
            case 49175:
            case 49176:
            case 49177:
                return 20;
            case 49178:
            case 49181:
            case 49184:
                return 21;
            case 49179:
            case 49182:
            case 49185:
                return 23;
            case 49180:
            case 49183:
            case 49186:
                return 22;
            case 49204:
            case 49205:
            case 49206:
            case 49207:
            case 49208:
            case 49209:
            case 49210:
            case 49211:
            case 49264:
            case 49265:
            case 49306:
            case 49307:
            case 52396:
            case 53249:
            case 53250:
            case 53251:
            case 53253:
                return 24;
            default:
                return -1;
        }
    }

    public static Vector getKeyExchangeAlgorithms(int[] cipherSuites) {
        Vector result = new Vector();
        if (null != cipherSuites) {
            for(int i = 0; i < cipherSuites.length; ++i) {
                addToSet(result, getKeyExchangeAlgorithm(cipherSuites[i]));
            }

            result.removeElement(Integers.valueOf(-1));
        }

        return result;
    }

    public static int getMACAlgorithm(int cipherSuite) {
        switch(cipherSuite) {
            case 2:
            case 10:
            case 13:
            case 16:
            case 19:
            case 22:
            case 27:
            case 44:
            case 45:
            case 46:
            case 47:
            case 48:
            case 49:
            case 50:
            case 51:
            case 52:
            case 53:
            case 54:
            case 55:
            case 56:
            case 57:
            case 58:
            case 65:
            case 66:
            case 67:
            case 68:
            case 69:
            case 70:
            case 132:
            case 133:
            case 134:
            case 135:
            case 136:
            case 137:
            case 139:
            case 140:
            case 141:
            case 143:
            case 144:
            case 145:
            case 147:
            case 148:
            case 149:
            case 150:
            case 151:
            case 152:
            case 153:
            case 154:
            case 155:
            case 49153:
            case 49155:
            case 49156:
            case 49157:
            case 49158:
            case 49160:
            case 49161:
            case 49162:
            case 49163:
            case 49165:
            case 49166:
            case 49167:
            case 49168:
            case 49170:
            case 49171:
            case 49172:
            case 49173:
            case 49175:
            case 49176:
            case 49177:
            case 49178:
            case 49179:
            case 49180:
            case 49181:
            case 49182:
            case 49183:
            case 49184:
            case 49185:
            case 49186:
            case 49204:
            case 49205:
            case 49206:
            case 49209:
                return 2;
            case 59:
            case 60:
            case 61:
            case 62:
            case 63:
            case 64:
            case 103:
            case 104:
            case 105:
            case 106:
            case 107:
            case 108:
            case 109:
            case 174:
            case 176:
            case 178:
            case 180:
            case 182:
            case 184:
            case 186:
            case 187:
            case 188:
            case 189:
            case 190:
            case 191:
            case 192:
            case 193:
            case 194:
            case 195:
            case 196:
            case 197:
            case 49187:
            case 49189:
            case 49191:
            case 49193:
            case 49207:
            case 49210:
            case 49212:
            case 49214:
            case 49216:
            case 49218:
            case 49220:
            case 49222:
            case 49224:
            case 49226:
            case 49228:
            case 49230:
            case 49252:
            case 49254:
            case 49256:
            case 49264:
            case 49266:
            case 49268:
            case 49270:
            case 49272:
            case 49300:
            case 49302:
            case 49304:
            case 49306:
                return 3;
            case 156:
            case 157:
            case 158:
            case 159:
            case 160:
            case 161:
            case 162:
            case 163:
            case 164:
            case 165:
            case 166:
            case 167:
            case 168:
            case 169:
            case 170:
            case 171:
            case 172:
            case 173:
            case 198:
            case 199:
            case 4865:
            case 4866:
            case 4867:
            case 4868:
            case 4869:
            case 49195:
            case 49196:
            case 49197:
            case 49198:
            case 49199:
            case 49200:
            case 49201:
            case 49202:
            case 49232:
            case 49233:
            case 49234:
            case 49235:
            case 49236:
            case 49237:
            case 49238:
            case 49239:
            case 49240:
            case 49241:
            case 49242:
            case 49243:
            case 49244:
            case 49245:
            case 49246:
            case 49247:
            case 49248:
            case 49249:
            case 49250:
            case 49251:
            case 49258:
            case 49259:
            case 49260:
            case 49261:
            case 49262:
            case 49263:
            case 49274:
            case 49275:
            case 49276:
            case 49277:
            case 49278:
            case 49279:
            case 49280:
            case 49281:
            case 49282:
            case 49283:
            case 49284:
            case 49285:
            case 49286:
            case 49287:
            case 49288:
            case 49289:
            case 49290:
            case 49291:
            case 49292:
            case 49293:
            case 49294:
            case 49295:
            case 49296:
            case 49297:
            case 49298:
            case 49299:
            case 49308:
            case 49309:
            case 49310:
            case 49311:
            case 49312:
            case 49313:
            case 49314:
            case 49315:
            case 49316:
            case 49317:
            case 49318:
            case 49319:
            case 49320:
            case 49321:
            case 49322:
            case 49323:
            case 49324:
            case 49325:
            case 49326:
            case 49327:
            case 52392:
            case 52393:
            case 52394:
            case 52395:
            case 52396:
            case 52397:
            case 52398:
            case 53249:
            case 53250:
            case 53251:
            case 53253:
                return 0;
            case 175:
            case 177:
            case 179:
            case 181:
            case 183:
            case 185:
            case 49188:
            case 49190:
            case 49192:
            case 49194:
            case 49208:
            case 49211:
            case 49213:
            case 49215:
            case 49217:
            case 49219:
            case 49221:
            case 49223:
            case 49225:
            case 49227:
            case 49229:
            case 49231:
            case 49253:
            case 49255:
            case 49257:
            case 49265:
            case 49267:
            case 49269:
            case 49271:
            case 49273:
            case 49301:
            case 49303:
            case 49305:
            case 49307:
                return 4;
            default:
                return -1;
        }
    }

    public static ProtocolVersion getMinimumVersion(int cipherSuite) {
        switch(cipherSuite) {
            case 59:
            case 60:
            case 61:
            case 62:
            case 63:
            case 64:
            case 103:
            case 104:
            case 105:
            case 106:
            case 107:
            case 108:
            case 109:
            case 156:
            case 157:
            case 158:
            case 159:
            case 160:
            case 161:
            case 162:
            case 163:
            case 164:
            case 165:
            case 166:
            case 167:
            case 168:
            case 169:
            case 170:
            case 171:
            case 172:
            case 173:
            case 186:
            case 187:
            case 188:
            case 189:
            case 190:
            case 191:
            case 192:
            case 193:
            case 194:
            case 195:
            case 196:
            case 197:
            case 49187:
            case 49188:
            case 49189:
            case 49190:
            case 49191:
            case 49192:
            case 49193:
            case 49194:
            case 49195:
            case 49196:
            case 49197:
            case 49198:
            case 49199:
            case 49200:
            case 49201:
            case 49202:
            case 49212:
            case 49213:
            case 49214:
            case 49215:
            case 49216:
            case 49217:
            case 49218:
            case 49219:
            case 49220:
            case 49221:
            case 49222:
            case 49223:
            case 49224:
            case 49225:
            case 49226:
            case 49227:
            case 49228:
            case 49229:
            case 49230:
            case 49231:
            case 49232:
            case 49233:
            case 49234:
            case 49235:
            case 49236:
            case 49237:
            case 49238:
            case 49239:
            case 49240:
            case 49241:
            case 49242:
            case 49243:
            case 49244:
            case 49245:
            case 49246:
            case 49247:
            case 49248:
            case 49249:
            case 49250:
            case 49251:
            case 49252:
            case 49253:
            case 49254:
            case 49255:
            case 49256:
            case 49257:
            case 49258:
            case 49259:
            case 49260:
            case 49261:
            case 49262:
            case 49263:
            case 49264:
            case 49265:
            case 49266:
            case 49267:
            case 49268:
            case 49269:
            case 49270:
            case 49271:
            case 49272:
            case 49273:
            case 49274:
            case 49275:
            case 49276:
            case 49277:
            case 49278:
            case 49279:
            case 49280:
            case 49281:
            case 49282:
            case 49283:
            case 49284:
            case 49285:
            case 49286:
            case 49287:
            case 49288:
            case 49289:
            case 49290:
            case 49291:
            case 49292:
            case 49293:
            case 49294:
            case 49295:
            case 49296:
            case 49297:
            case 49298:
            case 49299:
            case 49308:
            case 49309:
            case 49310:
            case 49311:
            case 49312:
            case 49313:
            case 49314:
            case 49315:
            case 49316:
            case 49317:
            case 49318:
            case 49319:
            case 49320:
            case 49321:
            case 49322:
            case 49323:
            case 49324:
            case 49325:
            case 49326:
            case 49327:
            case 52392:
            case 52393:
            case 52394:
            case 52395:
            case 52396:
            case 52397:
            case 52398:
            case 53249:
            case 53250:
            case 53251:
            case 53253:
                return ProtocolVersion.TLSv12;
            case 198:
            case 199:
            case 4865:
            case 4866:
            case 4867:
            case 4868:
            case 4869:
                return ProtocolVersion.TLSv13;
            default:
                return ProtocolVersion.SSLv3;
        }
    }

    public static Vector getNamedGroupRoles(int[] cipherSuites) {
        return getNamedGroupRoles(getKeyExchangeAlgorithms(cipherSuites));
    }

    public static Vector getNamedGroupRoles(Vector keyExchangeAlgorithms) {
        Vector result = new Vector();

        for(int i = 0; i < keyExchangeAlgorithms.size(); ++i) {
            int keyExchangeAlgorithm = (Integer)keyExchangeAlgorithms.elementAt(i);
            switch(keyExchangeAlgorithm) {
                case 0:
                    addToSet(result, 1);
                    addToSet(result, 2);
                case 1:
                case 2:
                case 4:
                case 6:
                case 8:
                case 10:
                case 12:
                case 13:
                case 15:
                case 21:
                case 22:
                case 23:
                default:
                    break;
                case 3:
                case 5:
                case 7:
                case 9:
                case 11:
                case 14:
                    addToSet(result, 1);
                    break;
                case 16:
                case 17:
                    addToSet(result, 2);
                    addToSet(result, 3);
                    break;
                case 18:
                case 19:
                case 20:
                case 24:
                    addToSet(result, 2);
            }
        }

        return result;
    }

    public static boolean isAEADCipherSuite(int cipherSuite) throws IOException {
        return 2 == getCipherType(cipherSuite);
    }

    public static boolean isBlockCipherSuite(int cipherSuite) throws IOException {
        return 1 == getCipherType(cipherSuite);
    }

    public static boolean isStreamCipherSuite(int cipherSuite) throws IOException {
        return 0 == getCipherType(cipherSuite);
    }

    public static boolean isValidCipherSuiteForSignatureAlgorithms(int cipherSuite, Vector sigAlgs) {
        int keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);
        switch(keyExchangeAlgorithm) {
            case 0:
            case 3:
            case 5:
            case 17:
            case 19:
            case 22:
            case 23:
                int count = sigAlgs.size();

                for(int i = 0; i < count; ++i) {
                    Short sigAlg = (Short)sigAlgs.elementAt(i);
                    if (null != sigAlg) {
                        short signatureAlgorithm = sigAlg;
                        if (isValidSignatureAlgorithmForServerKeyExchange(signatureAlgorithm, keyExchangeAlgorithm)) {
                            return true;
                        }
                    }
                }

                return false;
            case 1:
            case 2:
            case 4:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 18:
            case 20:
            case 21:
            default:
                return true;
        }
    }

    /** @deprecated */
    public static boolean isValidCipherSuiteForVersion(int cipherSuite, ProtocolVersion version) {
        return isValidVersionForCipherSuite(cipherSuite, version);
    }

    static boolean isValidCipherSuiteSelection(int[] offeredCipherSuites, int cipherSuite) {
        return null != offeredCipherSuites && Arrays.contains(offeredCipherSuites, cipherSuite) && 0 != cipherSuite && !CipherSuite.isSCSV(cipherSuite);
    }

    static boolean isValidKeyShareSelection(ProtocolVersion negotiatedVersion, int[] clientSupportedGroups, Hashtable clientAgreements, int keyShareGroup) {
        return null != clientSupportedGroups && Arrays.contains(clientSupportedGroups, keyShareGroup) && !clientAgreements.containsKey(Integers.valueOf(keyShareGroup)) && NamedGroup.canBeNegotiated(keyShareGroup, negotiatedVersion);
    }

    static boolean isValidSignatureAlgorithmForCertificateVerify(short signatureAlgorithm, short[] clientCertificateTypes) {
        short clientCertificateType = SignatureAlgorithm.getClientCertificateType(signatureAlgorithm);
        return clientCertificateType >= 0 && Arrays.contains(clientCertificateTypes, clientCertificateType);
    }

    static boolean isValidSignatureAlgorithmForServerKeyExchange(short signatureAlgorithm, int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 0:
                return 0 != signatureAlgorithm;
            case 1:
            case 2:
            case 4:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 18:
            case 20:
            case 21:
            default:
                return false;
            case 3:
            case 22:
                return 2 == signatureAlgorithm;
            case 5:
            case 19:
            case 23:
                switch(signatureAlgorithm) {
                    case 1:
                    case 4:
                    case 5:
                    case 6:
                    case 9:
                    case 10:
                    case 11:
                        return true;
                    case 2:
                    case 3:
                    case 7:
                    case 8:
                    default:
                        return false;
                }
            case 17:
                switch(signatureAlgorithm) {
                    case 3:
                    case 7:
                    case 8:
                        return true;
                    default:
                        return false;
                }
        }
    }

    public static boolean isValidSignatureSchemeForServerKeyExchange(int signatureScheme, int keyExchangeAlgorithm) {
        short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme);
        return isValidSignatureAlgorithmForServerKeyExchange(signatureAlgorithm, keyExchangeAlgorithm);
    }

    public static boolean isValidVersionForCipherSuite(int cipherSuite, ProtocolVersion version) {
        version = version.getEquivalentTLSVersion();
        ProtocolVersion minimumVersion = getMinimumVersion(cipherSuite);
        if (minimumVersion == version) {
            return true;
        } else if (!minimumVersion.isEarlierVersionOf(version)) {
            return false;
        } else {
            return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(minimumVersion) || ProtocolVersion.TLSv13.isLaterVersionOf(version);
        }
    }

    public static SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm(TlsContext context, Vector sigHashAlgs, short signatureAlgorithm) throws IOException {
        return chooseSignatureAndHashAlgorithm(context.getServerVersion(), sigHashAlgs, signatureAlgorithm);
    }

    public static SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm(ProtocolVersion negotiatedVersion, Vector sigHashAlgs, short signatureAlgorithm) throws IOException {
        if (!isTLSv12(negotiatedVersion)) {
            return null;
        } else {
            if (sigHashAlgs == null) {
                sigHashAlgs = getDefaultSignatureAlgorithms(signatureAlgorithm);
            }

            SignatureAndHashAlgorithm result = null;

            for(int i = 0; i < sigHashAlgs.size(); ++i) {
                SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm)sigHashAlgs.elementAt(i);
                if (sigHashAlg.getSignature() == signatureAlgorithm) {
                    short hash = sigHashAlg.getHash();
                    if (hash >= 2) {
                        if (result == null) {
                            result = sigHashAlg;
                        } else {
                            short current = result.getHash();
                            if (current < 4) {
                                if (hash > current) {
                                    result = sigHashAlg;
                                }
                            } else if (hash >= 4 && hash < current) {
                                result = sigHashAlg;
                            }
                        }
                    }
                }
            }

            if (result == null) {
                throw new TlsFatalAlert((short)80);
            } else {
                return result;
            }
        }
    }

    public static Vector getUsableSignatureAlgorithms(Vector sigHashAlgs) {
        Vector v;
        if (sigHashAlgs == null) {
            v = new Vector(3);
            v.addElement(Shorts.valueOf((short)1));
            v.addElement(Shorts.valueOf((short)2));
            v.addElement(Shorts.valueOf((short)3));
            return v;
        } else {
            v = new Vector();

            for(int i = 0; i < sigHashAlgs.size(); ++i) {
                SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm)sigHashAlgs.elementAt(i);
                if (sigHashAlg.getHash() >= 2) {
                    Short sigAlg = Shorts.valueOf(sigHashAlg.getSignature());
                    if (!v.contains(sigAlg)) {
                        v.addElement(sigAlg);
                    }
                }
            }

            return v;
        }
    }

    public static int getCommonCipherSuite13(ProtocolVersion negotiatedVersion, int[] peerCipherSuites, int[] localCipherSuites, boolean useLocalOrder) {
        int[] ordered = peerCipherSuites;
        int[] unordered = localCipherSuites;
        if (useLocalOrder) {
            ordered = localCipherSuites;
            unordered = peerCipherSuites;
        }

        for(int i = 0; i < ordered.length; ++i) {
            int candidate = ordered[i];
            if (Arrays.contains(unordered, candidate) && isValidVersionForCipherSuite(candidate, negotiatedVersion)) {
                return candidate;
            }
        }

        return -1;
    }

    public static int[] getCommonCipherSuites(int[] peerCipherSuites, int[] localCipherSuites, boolean useLocalOrder) {
        int[] ordered = peerCipherSuites;
        int[] unordered = localCipherSuites;
        if (useLocalOrder) {
            ordered = localCipherSuites;
            unordered = peerCipherSuites;
        }

        int count = 0;
        int limit = Math.min(ordered.length, unordered.length);
        int[] candidates = new int[limit];

        for(int i = 0; i < ordered.length; ++i) {
            int candidate = ordered[i];
            if (!contains(candidates, 0, count, candidate) && Arrays.contains(unordered, candidate)) {
                candidates[count++] = candidate;
            }
        }

        if (count < limit) {
            candidates = Arrays.copyOf(candidates, count);
        }

        return candidates;
    }

    public static int[] getSupportedCipherSuites(TlsCrypto crypto, int[] suites) {
        return getSupportedCipherSuites(crypto, suites, 0, suites.length);
    }

    /** @deprecated */
    public static int[] getSupportedCipherSuites(TlsCrypto crypto, int[] suites, int suitesCount) {
        return getSupportedCipherSuites(crypto, suites, 0, suitesCount);
    }

    public static int[] getSupportedCipherSuites(TlsCrypto crypto, int[] suites, int suitesOff, int suitesCount) {
        int[] supported = new int[suitesCount];
        int count = 0;

        for(int i = 0; i < suitesCount; ++i) {
            int suite = suites[suitesOff + i];
            if (isSupportedCipherSuite(crypto, suite)) {
                supported[count++] = suite;
            }
        }

        if (count < suitesCount) {
            supported = Arrays.copyOf(supported, count);
        }

        return supported;
    }

    public static boolean isSupportedCipherSuite(TlsCrypto crypto, int cipherSuite) {
        int keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);
        if (!isSupportedKeyExchange(crypto, keyExchangeAlgorithm)) {
            return false;
        } else {
            int encryptionAlgorithm = getEncryptionAlgorithm(cipherSuite);
            if (encryptionAlgorithm >= 0 && crypto.hasEncryptionAlgorithm(encryptionAlgorithm)) {
                int macAlgorithm = getMACAlgorithm(cipherSuite);
                return macAlgorithm == 0 || macAlgorithm >= 0 && crypto.hasMacAlgorithm(macAlgorithm);
            } else {
                return false;
            }
        }
    }

    public static boolean isSupportedKeyExchange(TlsCrypto crypto, int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 0:
            case 13:
                return true;
            case 1:
            case 15:
                return crypto.hasRSAEncryption();
            case 2:
            case 4:
            case 6:
            case 8:
            case 10:
            case 12:
            default:
                return false;
            case 3:
                return crypto.hasDHAgreement() && crypto.hasSignatureAlgorithm((short)2);
            case 5:
                return crypto.hasDHAgreement() && hasAnyRSASigAlgs(crypto);
            case 7:
            case 9:
            case 11:
            case 14:
                return crypto.hasDHAgreement();
            case 16:
            case 18:
            case 20:
            case 24:
                return crypto.hasECDHAgreement();
            case 17:
                return crypto.hasECDHAgreement() && (crypto.hasSignatureAlgorithm((short)3) || crypto.hasSignatureAlgorithm((short)7) || crypto.hasSignatureAlgorithm((short)8));
            case 19:
                return crypto.hasECDHAgreement() && hasAnyRSASigAlgs(crypto);
            case 21:
                return crypto.hasSRPAuthentication();
            case 22:
                return crypto.hasSRPAuthentication() && crypto.hasSignatureAlgorithm((short)2);
            case 23:
                return crypto.hasSRPAuthentication() && hasAnyRSASigAlgs(crypto);
        }
    }

    static boolean hasAnyRSASigAlgs(TlsCrypto crypto) {
        return crypto.hasSignatureAlgorithm((short)1) || crypto.hasSignatureAlgorithm((short)4) || crypto.hasSignatureAlgorithm((short)5) || crypto.hasSignatureAlgorithm((short)6) || crypto.hasSignatureAlgorithm((short)9) || crypto.hasSignatureAlgorithm((short)10) || crypto.hasSignatureAlgorithm((short)11);
    }

    static byte[] getCurrentPRFHash(TlsHandshakeHash handshakeHash) {
        return handshakeHash.forkPRFHash().calculateHash();
    }

    static void sealHandshakeHash(TlsContext context, TlsHandshakeHash handshakeHash, boolean forceBuffering) {
        if (forceBuffering || !context.getCrypto().hasAllRawSignatureAlgorithms()) {
            handshakeHash.forceBuffering();
        }

        handshakeHash.sealHashAlgorithms();
    }

    private static TlsHash createHash(TlsCrypto crypto, short hashAlgorithm) {
        int cryptoHashAlgorithm = TlsCryptoUtils.getHash(hashAlgorithm);
        return crypto.createHash(cryptoHashAlgorithm);
    }

    private static TlsKeyExchange createKeyExchangeClient(TlsClient client, int keyExchange) throws IOException {
        TlsKeyExchangeFactory factory = client.getKeyExchangeFactory();
        switch(keyExchange) {
            case 1:
                return factory.createRSAKeyExchange(keyExchange);
            case 2:
            case 4:
            case 6:
            case 8:
            case 10:
            case 12:
            default:
                throw new TlsFatalAlert((short)80);
            case 3:
            case 5:
                return factory.createDHEKeyExchangeClient(keyExchange, client.getDHGroupVerifier());
            case 7:
            case 9:
                return factory.createDHKeyExchange(keyExchange);
            case 11:
                return factory.createDHanonKeyExchangeClient(keyExchange, client.getDHGroupVerifier());
            case 13:
            case 15:
            case 24:
                return factory.createPSKKeyExchangeClient(keyExchange, client.getPSKIdentity(), (TlsDHGroupVerifier)null);
            case 14:
                return factory.createPSKKeyExchangeClient(keyExchange, client.getPSKIdentity(), client.getDHGroupVerifier());
            case 16:
            case 18:
                return factory.createECDHKeyExchange(keyExchange);
            case 17:
            case 19:
                return factory.createECDHEKeyExchangeClient(keyExchange);
            case 20:
                return factory.createECDHanonKeyExchangeClient(keyExchange);
            case 21:
            case 22:
            case 23:
                return factory.createSRPKeyExchangeClient(keyExchange, client.getSRPIdentity(), client.getSRPConfigVerifier());
        }
    }

    private static TlsKeyExchange createKeyExchangeServer(TlsServer server, int keyExchange) throws IOException {
        TlsKeyExchangeFactory factory = server.getKeyExchangeFactory();
        switch(keyExchange) {
            case 1:
                return factory.createRSAKeyExchange(keyExchange);
            case 2:
            case 4:
            case 6:
            case 8:
            case 10:
            case 12:
            default:
                throw new TlsFatalAlert((short)80);
            case 3:
            case 5:
                return factory.createDHEKeyExchangeServer(keyExchange, server.getDHConfig());
            case 7:
            case 9:
                return factory.createDHKeyExchange(keyExchange);
            case 11:
                return factory.createDHanonKeyExchangeServer(keyExchange, server.getDHConfig());
            case 13:
            case 15:
                return factory.createPSKKeyExchangeServer(keyExchange, server.getPSKIdentityManager(), (TlsDHConfig)null, (TlsECConfig)null);
            case 14:
                return factory.createPSKKeyExchangeServer(keyExchange, server.getPSKIdentityManager(), server.getDHConfig(), (TlsECConfig)null);
            case 16:
            case 18:
                return factory.createECDHKeyExchange(keyExchange);
            case 17:
            case 19:
                return factory.createECDHEKeyExchangeServer(keyExchange, server.getECDHConfig());
            case 20:
                return factory.createECDHanonKeyExchangeServer(keyExchange, server.getECDHConfig());
            case 21:
            case 22:
            case 23:
                return factory.createSRPKeyExchangeServer(keyExchange, server.getSRPLoginParameters());
            case 24:
                return factory.createPSKKeyExchangeServer(keyExchange, server.getPSKIdentityManager(), (TlsDHConfig)null, server.getECDHConfig());
        }
    }

    static TlsKeyExchange initKeyExchangeClient(TlsClientContext clientContext, TlsClient client) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        TlsKeyExchange keyExchange = createKeyExchangeClient(client, securityParameters.getKeyExchangeAlgorithm());
        keyExchange.init(clientContext);
        return keyExchange;
    }

    static TlsKeyExchange initKeyExchangeServer(TlsServerContext serverContext, TlsServer server) throws IOException {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        TlsKeyExchange keyExchange = createKeyExchangeServer(server, securityParameters.getKeyExchangeAlgorithm());
        keyExchange.init(serverContext);
        return keyExchange;
    }

    static TlsCipher initCipher(TlsContext context) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        int cipherSuite = securityParameters.getCipherSuite();
        int encryptionAlgorithm = getEncryptionAlgorithm(cipherSuite);
        int macAlgorithm = getMACAlgorithm(cipherSuite);
        if (encryptionAlgorithm >= 0 && macAlgorithm >= 0) {
            return context.getCrypto().createCipher(new TlsCryptoParameters(context), encryptionAlgorithm, macAlgorithm);
        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    public static void checkPeerSigAlgs(TlsContext context, TlsCertificate[] peerCertPath) throws IOException {
        if (context.isServer()) {
            checkSigAlgOfClientCerts(context, peerCertPath);
        } else {
            checkSigAlgOfServerCerts(context, peerCertPath);
        }

    }

    private static void checkSigAlgOfClientCerts(TlsContext context, TlsCertificate[] clientCertPath) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        short[] clientCertTypes = securityParameters.getClientCertTypes();
        Vector serverSigAlgsCert = securityParameters.getServerSigAlgsCert();
        int trustAnchorPos = clientCertPath.length - 1;

        for(int i = 0; i < trustAnchorPos; ++i) {
            TlsCertificate subjectCert = clientCertPath[i];
            TlsCertificate issuerCert = clientCertPath[i + 1];
            SignatureAndHashAlgorithm sigAndHashAlg = getCertSigAndHashAlg(subjectCert, issuerCert);
            boolean valid = false;
            if (null != sigAndHashAlg) {
                if (null == serverSigAlgsCert) {
                    if (null != clientCertTypes) {
                        for(int j = 0; j < clientCertTypes.length; ++j) {
                            short signatureAlgorithm = getLegacySignatureAlgorithmClientCert(clientCertTypes[j]);
                            if (sigAndHashAlg.getSignature() == signatureAlgorithm) {
                                valid = true;
                                break;
                            }
                        }
                    }
                } else {
                    valid = containsSignatureAlgorithm(serverSigAlgsCert, sigAndHashAlg);
                }
            }

            if (!valid) {
                throw new TlsFatalAlert((short)42);
            }
        }

    }

    private static void checkSigAlgOfServerCerts(TlsContext context, TlsCertificate[] serverCertPath) throws IOException {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        Vector clientSigAlgsCert = securityParameters.getClientSigAlgsCert();
        Vector clientSigAlgs = securityParameters.getClientSigAlgs();
        if (clientSigAlgs == clientSigAlgsCert || isTLSv13(securityParameters.getNegotiatedVersion())) {
            clientSigAlgs = null;
        }

        int trustAnchorPos = serverCertPath.length - 1;

        for(int i = 0; i < trustAnchorPos; ++i) {
            TlsCertificate subjectCert = serverCertPath[i];
            TlsCertificate issuerCert = serverCertPath[i + 1];
            SignatureAndHashAlgorithm sigAndHashAlg = getCertSigAndHashAlg(subjectCert, issuerCert);
            boolean valid = false;
            if (null != sigAndHashAlg) {
                if (null == clientSigAlgsCert) {
                    short signatureAlgorithm = getLegacySignatureAlgorithmServerCert(securityParameters.getKeyExchangeAlgorithm());
                    valid = signatureAlgorithm == sigAndHashAlg.getSignature();
                } else {
                    valid = containsSignatureAlgorithm(clientSigAlgsCert, sigAndHashAlg) || null != clientSigAlgs && containsSignatureAlgorithm(clientSigAlgs, sigAndHashAlg);
                }
            }

            if (!valid) {
                throw new TlsFatalAlert((short)42);
            }
        }

    }

    static void checkTlsFeatures(Certificate serverCertificate, Hashtable clientExtensions, Hashtable serverExtensions) throws IOException {
        byte[] tlsFeatures = serverCertificate.getCertificateAt(0).getExtension(TlsObjectIdentifiers.id_pe_tlsfeature);
        if (tlsFeatures != null) {
            ASN1Sequence tlsFeaturesSeq = (ASN1Sequence)readASN1Object(tlsFeatures);

            int i;
            for(i = 0; i < tlsFeaturesSeq.size(); ++i) {
                if (!(tlsFeaturesSeq.getObjectAt(i) instanceof ASN1Integer)) {
                    throw new TlsFatalAlert((short)42);
                }
            }

            requireDEREncoding(tlsFeaturesSeq, tlsFeatures);

            for(i = 0; i < tlsFeaturesSeq.size(); ++i) {
                BigInteger tlsExtension = ((ASN1Integer)tlsFeaturesSeq.getObjectAt(i)).getPositiveValue();
                if (tlsExtension.bitLength() <= 16) {
                    Integer extensionType = Integers.valueOf(tlsExtension.intValue());
                    if (clientExtensions.containsKey(extensionType) && !serverExtensions.containsKey(extensionType)) {
                        throw new TlsFatalAlert((short)46);
                    }
                }
            }
        }

    }

    static void processClientCertificate(TlsServerContext serverContext, Certificate clientCertificate, TlsKeyExchange keyExchange, TlsServer server) throws IOException {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate()) {
            throw new TlsFatalAlert((short)10);
        } else {
            boolean isTLSv13 = isTLSv13(securityParameters.getNegotiatedVersion());
            if (!isTLSv13) {
                if (clientCertificate.isEmpty()) {
                    keyExchange.skipClientCredentials();
                } else {
                    keyExchange.processClientCertificate(clientCertificate);
                }
            }

            securityParameters.peerCertificate = clientCertificate;
            server.notifyClientCertificate(clientCertificate);
        }
    }

    static void processServerCertificate(TlsClientContext clientContext, CertificateStatus serverCertificateStatus, TlsKeyExchange keyExchange, TlsAuthentication clientAuthentication, Hashtable clientExtensions, Hashtable serverExtensions) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        boolean isTLSv13 = isTLSv13(securityParameters.getNegotiatedVersion());
        if (null == clientAuthentication) {
            if (isTLSv13) {
                throw new TlsFatalAlert((short)80);
            } else if (securityParameters.isRenegotiating()) {
                throw new TlsFatalAlert((short)40);
            } else {
                keyExchange.skipServerCredentials();
                securityParameters.tlsServerEndPoint = EMPTY_BYTES;
            }
        } else {
            Certificate serverCertificate = securityParameters.getPeerCertificate();
            checkTlsFeatures(serverCertificate, clientExtensions, serverExtensions);
            if (!isTLSv13) {
                keyExchange.processServerCertificate(serverCertificate);
            }

            clientAuthentication.notifyServerCertificate(new TlsServerCertificateImpl(serverCertificate, serverCertificateStatus));
        }
    }

    static SignatureAndHashAlgorithm getCertSigAndHashAlg(TlsCertificate subjectCert, TlsCertificate issuerCert) throws IOException {
        String sigAlgOID = subjectCert.getSigAlgOID();
        if (null != sigAlgOID) {
            if (!PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID)) {
                return (SignatureAndHashAlgorithm)CERT_SIG_ALG_OIDS.get(sigAlgOID);
            }

            RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(subjectCert.getSigAlgParams());
            if (null != pssParams) {
                ASN1ObjectIdentifier hashOID = pssParams.getHashAlgorithm().getAlgorithm();
                if (NISTObjectIdentifiers.id_sha256.equals(hashOID)) {
                    if (issuerCert.supportsSignatureAlgorithmCA((short)9)) {
                        return SignatureAndHashAlgorithm.rsa_pss_pss_sha256;
                    }

                    if (issuerCert.supportsSignatureAlgorithmCA((short)4)) {
                        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                    }
                } else if (NISTObjectIdentifiers.id_sha384.equals(hashOID)) {
                    if (issuerCert.supportsSignatureAlgorithmCA((short)10)) {
                        return SignatureAndHashAlgorithm.rsa_pss_pss_sha384;
                    }

                    if (issuerCert.supportsSignatureAlgorithmCA((short)5)) {
                        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha384;
                    }
                } else if (NISTObjectIdentifiers.id_sha512.equals(hashOID)) {
                    if (issuerCert.supportsSignatureAlgorithmCA((short)11)) {
                        return SignatureAndHashAlgorithm.rsa_pss_pss_sha512;
                    }

                    if (issuerCert.supportsSignatureAlgorithmCA((short)6)) {
                        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha512;
                    }
                }
            }
        }

        return null;
    }

    static CertificateRequest validateCertificateRequest(CertificateRequest certificateRequest, TlsKeyExchange keyExchange) throws IOException {
        short[] validClientCertificateTypes = keyExchange.getClientCertificateTypes();
        if (isNullOrEmpty(validClientCertificateTypes)) {
            throw new TlsFatalAlert((short)10);
        } else {
            certificateRequest = normalizeCertificateRequest(certificateRequest, validClientCertificateTypes);
            if (certificateRequest == null) {
                throw new TlsFatalAlert((short)47);
            } else {
                return certificateRequest;
            }
        }
    }

    static CertificateRequest normalizeCertificateRequest(CertificateRequest certificateRequest, short[] validClientCertificateTypes) {
        if (containsAll(validClientCertificateTypes, certificateRequest.getCertificateTypes())) {
            return certificateRequest;
        } else {
            short[] retained = retainAll(certificateRequest.getCertificateTypes(), validClientCertificateTypes);
            return retained.length < 1 ? null : new CertificateRequest(retained, certificateRequest.getSupportedSignatureAlgorithms(), certificateRequest.getCertificateAuthorities());
        }
    }

    static boolean contains(int[] buf, int off, int len, int value) {
        for(int i = 0; i < len; ++i) {
            if (value == buf[off + i]) {
                return true;
            }
        }

        return false;
    }

    static boolean containsAll(short[] container, short[] elements) {
        for(int i = 0; i < elements.length; ++i) {
            if (!Arrays.contains(container, elements[i])) {
                return false;
            }
        }

        return true;
    }

    static short[] retainAll(short[] retainer, short[] elements) {
        short[] retained = new short[Math.min(retainer.length, elements.length)];
        int count = 0;

        for(int i = 0; i < elements.length; ++i) {
            if (Arrays.contains(retainer, elements[i])) {
                retained[count++] = elements[i];
            }
        }

        return truncate(retained, count);
    }

    static short[] truncate(short[] a, int n) {
        if (n >= a.length) {
            return a;
        } else {
            short[] t = new short[n];
            System.arraycopy(a, 0, t, 0, n);
            return t;
        }
    }

    static int[] truncate(int[] a, int n) {
        if (n >= a.length) {
            return a;
        } else {
            int[] t = new int[n];
            System.arraycopy(a, 0, t, 0, n);
            return t;
        }
    }

    static TlsCredentialedAgreement requireAgreementCredentials(TlsCredentials credentials) throws IOException {
        if (!(credentials instanceof TlsCredentialedAgreement)) {
            throw new TlsFatalAlert((short)80);
        } else {
            return (TlsCredentialedAgreement)credentials;
        }
    }

    static TlsCredentialedDecryptor requireDecryptorCredentials(TlsCredentials credentials) throws IOException {
        if (!(credentials instanceof TlsCredentialedDecryptor)) {
            throw new TlsFatalAlert((short)80);
        } else {
            return (TlsCredentialedDecryptor)credentials;
        }
    }

    static TlsCredentialedSigner requireSignerCredentials(TlsCredentials credentials) throws IOException {
        if (!(credentials instanceof TlsCredentialedSigner)) {
            throw new TlsFatalAlert((short)80);
        } else {
            return (TlsCredentialedSigner)credentials;
        }
    }

    private static void checkDowngradeMarker(byte[] randomBlock, byte[] downgradeMarker) throws IOException {
        int len = downgradeMarker.length;
        if (constantTimeAreEqual(len, downgradeMarker, 0, randomBlock, randomBlock.length - len)) {
            throw new TlsFatalAlert((short)47);
        }
    }

    static void checkDowngradeMarker(ProtocolVersion version, byte[] randomBlock) throws IOException {
        version = version.getEquivalentTLSVersion();
        if (version.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv11)) {
            checkDowngradeMarker(randomBlock, DOWNGRADE_TLS11);
        }

        if (version.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv12)) {
            checkDowngradeMarker(randomBlock, DOWNGRADE_TLS12);
        }

    }

    static void writeDowngradeMarker(ProtocolVersion version, byte[] randomBlock) throws IOException {
        version = version.getEquivalentTLSVersion();
        byte[] marker;
        if (ProtocolVersion.TLSv12 == version) {
            marker = DOWNGRADE_TLS12;
        } else {
            if (!version.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv11)) {
                throw new TlsFatalAlert((short)80);
            }

            marker = DOWNGRADE_TLS11;
        }

        System.arraycopy(marker, 0, randomBlock, randomBlock.length - marker.length, marker.length);
    }

    private static boolean areCertificatesEqual(Certificate a, Certificate b) {
        int length = a.getLength();
        if (b.getLength() == length) {
            try {
                for(int i = 0; i < length; ++i) {
                    TlsCertificate ai = a.getCertificateAt(i);
                    TlsCertificate bi = b.getCertificateAt(i);
                    if (!Arrays.areEqual(ai.getEncoded(), bi.getEncoded())) {
                        return false;
                    }
                }

                return true;
            } catch (IOException var6) {
            }
        }

        return false;
    }

    private static boolean isSafeRenegotiationServerCertificate(TlsClientContext clientContext, Certificate serverCertificate) {
        SecurityParameters securityParametersConnection = clientContext.getSecurityParametersConnection();
        if (securityParametersConnection != null) {
            Certificate previousCertificate = securityParametersConnection.getPeerCertificate();
            if (null != previousCertificate) {
                return areCertificatesEqual(previousCertificate, serverCertificate);
            }
        }

        return false;
    }

    static TlsAuthentication receiveServerCertificate(TlsClientContext clientContext, TlsClient client, ByteArrayInputStream buf) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate()) {
            throw new TlsFatalAlert((short)10);
        } else {
            ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
            ParseOptions options = (new ParseOptions()).setMaxChainLength(client.getMaxCertificateChainLength());
            Certificate serverCertificate = Certificate.parse(options, clientContext, buf, endPointHash);
            TlsProtocol.assertEmpty(buf);
            if (serverCertificate.isEmpty()) {
                throw new TlsFatalAlert((short)50);
            } else if (securityParameters.isRenegotiating() && !isSafeRenegotiationServerCertificate(clientContext, serverCertificate)) {
                throw new TlsFatalAlert((short)46, "Server certificate changed unsafely in renegotiation handshake");
            } else {
                securityParameters.peerCertificate = serverCertificate;
                securityParameters.tlsServerEndPoint = endPointHash.toByteArray();
                TlsAuthentication authentication = client.getAuthentication();
                if (null == authentication) {
                    throw new TlsFatalAlert((short)80);
                } else {
                    return authentication;
                }
            }
        }
    }

    static TlsAuthentication receive13ServerCertificate(TlsClientContext clientContext, TlsClient client, ByteArrayInputStream buf) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate()) {
            throw new TlsFatalAlert((short)10);
        } else {
            ParseOptions options = (new ParseOptions()).setMaxChainLength(client.getMaxCertificateChainLength());
            Certificate serverCertificate = Certificate.parse(options, clientContext, buf, (OutputStream)null);
            TlsProtocol.assertEmpty(buf);
            if (serverCertificate.getCertificateRequestContext().length > 0) {
                throw new TlsFatalAlert((short)47);
            } else if (serverCertificate.isEmpty()) {
                throw new TlsFatalAlert((short)50);
            } else {
                securityParameters.peerCertificate = serverCertificate;
                securityParameters.tlsServerEndPoint = null;
                TlsAuthentication authentication = client.getAuthentication();
                if (null == authentication) {
                    throw new TlsFatalAlert((short)80);
                } else {
                    return authentication;
                }
            }
        }
    }

    static TlsAuthentication skip13ServerCertificate(TlsClientContext clientContext) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        if (null != securityParameters.getPeerCertificate()) {
            throw new TlsFatalAlert((short)80);
        } else {
            securityParameters.peerCertificate = null;
            securityParameters.tlsServerEndPoint = null;
            return null;
        }
    }

    public static boolean containsNonAscii(byte[] bs) {
        for(int i = 0; i < bs.length; ++i) {
            int c = bs[i] & 255;
            if (c >= 128) {
                return true;
            }
        }

        return false;
    }

    public static boolean containsNonAscii(String s) {
        for(int i = 0; i < s.length(); ++i) {
            int c = s.charAt(i);
            if (c >= 128) {
                return true;
            }
        }

        return false;
    }

    static Hashtable addKeyShareToClientHello(TlsClientContext clientContext, TlsClient client, Hashtable clientExtensions) throws IOException {
        if (isTLSv13(clientContext.getClientVersion()) && clientExtensions.containsKey(TlsExtensionsUtils.EXT_supported_groups)) {
            int[] supportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);
            Vector keyShareGroups = client.getEarlyKeyShareGroups();
            Hashtable clientAgreements = new Hashtable(3);
            Vector clientShares = new Vector(2);
            collectKeyShares(clientContext.getCrypto(), supportedGroups, keyShareGroups, clientAgreements, clientShares);
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, clientShares);
            return clientAgreements;
        } else {
            return null;
        }
    }

    static Hashtable addKeyShareToClientHelloRetry(TlsClientContext clientContext, Hashtable clientExtensions, int keyShareGroup) throws IOException {
        int[] supportedGroups = new int[]{keyShareGroup};
        Vector keyShareGroups = vectorOfOne(Integers.valueOf(keyShareGroup));
        Hashtable clientAgreements = new Hashtable(1, 1.0F);
        Vector clientShares = new Vector(1);
        collectKeyShares(clientContext.getCrypto(), supportedGroups, keyShareGroups, clientAgreements, clientShares);
        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, clientShares);
        if (!clientAgreements.isEmpty() && !clientShares.isEmpty()) {
            return clientAgreements;
        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    private static void collectKeyShares(TlsCrypto crypto, int[] supportedGroups, Vector keyShareGroups, Hashtable clientAgreements, Vector clientShares) throws IOException {
        if (!isNullOrEmpty(supportedGroups)) {
            if (null != keyShareGroups && !keyShareGroups.isEmpty()) {
                for(int i = 0; i < supportedGroups.length; ++i) {
                    int supportedGroup = supportedGroups[i];
                    Integer supportedGroupElement = Integers.valueOf(supportedGroup);
                    if (keyShareGroups.contains(supportedGroupElement) && !clientAgreements.containsKey(supportedGroupElement) && crypto.hasNamedGroup(supportedGroup)) {
                        TlsAgreement agreement = null;
                        if (NamedGroup.refersToASpecificCurve(supportedGroup)) {
                            if (crypto.hasECDHAgreement()) {
                                agreement = crypto.createECDomain(new TlsECConfig(supportedGroup)).createECDH();
                            }
                        } else if (NamedGroup.refersToASpecificFiniteField(supportedGroup) && crypto.hasDHAgreement()) {
                            agreement = crypto.createDHDomain(new TlsDHConfig(supportedGroup, true)).createDH();
                        }

                        if (null != agreement) {
                            byte[] key_exchange = agreement.generateEphemeral();
                            KeyShareEntry clientShare = new KeyShareEntry(supportedGroup, key_exchange);
                            clientShares.addElement(clientShare);
                            clientAgreements.put(supportedGroupElement, agreement);
                        }
                    }
                }

            }
        }
    }

    static KeyShareEntry selectKeyShare(Vector clientShares, int keyShareGroup) {
        if (null != clientShares && 1 == clientShares.size()) {
            KeyShareEntry clientShare = (KeyShareEntry)clientShares.elementAt(0);
            if (null != clientShare && clientShare.getNamedGroup() == keyShareGroup) {
                return clientShare;
            }
        }

        return null;
    }

    static KeyShareEntry selectKeyShare(TlsCrypto crypto, ProtocolVersion negotiatedVersion, Vector clientShares, int[] clientSupportedGroups, int[] serverSupportedGroups) {
        if (null != clientShares && !isNullOrEmpty(clientSupportedGroups) && !isNullOrEmpty(serverSupportedGroups)) {
            for(int i = 0; i < clientShares.size(); ++i) {
                KeyShareEntry clientShare = (KeyShareEntry)clientShares.elementAt(i);
                int group = clientShare.getNamedGroup();
                if (NamedGroup.canBeNegotiated(group, negotiatedVersion) && Arrays.contains(serverSupportedGroups, group) && Arrays.contains(clientSupportedGroups, group) && crypto.hasNamedGroup(group) && (!NamedGroup.refersToASpecificCurve(group) || crypto.hasECDHAgreement()) && (!NamedGroup.refersToASpecificFiniteField(group) || crypto.hasDHAgreement())) {
                    return clientShare;
                }
            }
        }

        return null;
    }

    static int selectKeyShareGroup(TlsCrypto crypto, ProtocolVersion negotiatedVersion, int[] clientSupportedGroups, int[] serverSupportedGroups) {
        if (!isNullOrEmpty(clientSupportedGroups) && !isNullOrEmpty(serverSupportedGroups)) {
            for(int i = 0; i < clientSupportedGroups.length; ++i) {
                int group = clientSupportedGroups[i];
                if (NamedGroup.canBeNegotiated(group, negotiatedVersion) && Arrays.contains(serverSupportedGroups, group) && crypto.hasNamedGroup(group) && (!NamedGroup.refersToASpecificCurve(group) || crypto.hasECDHAgreement()) && (!NamedGroup.refersToASpecificFiniteField(group) || crypto.hasDHAgreement())) {
                    return group;
                }
            }
        }

        return -1;
    }

    static byte[] readEncryptedPMS(TlsContext context, InputStream input) throws IOException {
        return isSSL(context) ? SSL3Utils.readEncryptedPMS(input) : readOpaque16(input);
    }

    static void writeEncryptedPMS(TlsContext context, byte[] encryptedPMS, OutputStream output) throws IOException {
        if (isSSL(context)) {
            SSL3Utils.writeEncryptedPMS(encryptedPMS, output);
        } else {
            writeOpaque16(encryptedPMS, output);
        }

    }

    static byte[] getSessionID(TlsSession tlsSession) {
        if (null != tlsSession) {
            byte[] sessionID = tlsSession.getSessionID();
            if (null != sessionID && sessionID.length > 0 && sessionID.length <= 32) {
                return sessionID;
            }
        }

        return EMPTY_BYTES;
    }

    static void adjustTranscriptForRetry(TlsHandshakeHash handshakeHash) throws IOException {
        byte[] clientHelloHash = getCurrentPRFHash(handshakeHash);
        handshakeHash.reset();
        int length = clientHelloHash.length;
        checkUint8(length);
        byte[] synthetic = new byte[4 + length];
        writeUint8((short)254, synthetic, 0);
        writeUint24(length, synthetic, 1);
        System.arraycopy(clientHelloHash, 0, synthetic, 4, length);
        handshakeHash.update(synthetic, 0, synthetic.length);
    }

    static TlsCredentials establishClientCredentials(TlsAuthentication clientAuthentication, CertificateRequest certificateRequest) throws IOException {
        return validateCredentials(clientAuthentication.getClientCredentials(certificateRequest));
    }

    static TlsCredentialedSigner establish13ClientCredentials(TlsAuthentication clientAuthentication, CertificateRequest certificateRequest) throws IOException {
        return validate13Credentials(clientAuthentication.getClientCredentials(certificateRequest));
    }

    static void establishClientSigAlgs(SecurityParameters securityParameters, Hashtable clientExtensions) throws IOException {
        securityParameters.clientSigAlgs = TlsExtensionsUtils.getSignatureAlgorithmsExtension(clientExtensions);
        securityParameters.clientSigAlgsCert = TlsExtensionsUtils.getSignatureAlgorithmsCertExtension(clientExtensions);
    }

    static TlsCredentials establishServerCredentials(TlsServer server) throws IOException {
        return validateCredentials(server.getCredentials());
    }

    static TlsCredentialedSigner establish13ServerCredentials(TlsServer server) throws IOException {
        return validate13Credentials(server.getCredentials());
    }

    static void establishServerSigAlgs(SecurityParameters securityParameters, CertificateRequest certificateRequest) throws IOException {
        securityParameters.clientCertTypes = certificateRequest.getCertificateTypes();
        securityParameters.serverSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
        securityParameters.serverSigAlgsCert = certificateRequest.getSupportedSignatureAlgorithmsCert();
        if (null == securityParameters.getServerSigAlgsCert()) {
            securityParameters.serverSigAlgsCert = securityParameters.getServerSigAlgs();
        }

    }

    static TlsCredentials validateCredentials(TlsCredentials credentials) throws IOException {
        if (null != credentials)
        {
            int count = 0;
            count += (credentials instanceof TlsCredentialedAgreement) ? 1 : 0;
            count += (credentials instanceof TlsCredentialedDecryptor) ? 1 : 0;
            count += (credentials instanceof TlsCredentialedSigner) ? 1 : 0;
            if (count != 1)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        return credentials;
    }

    static TlsCredentialedSigner validate13Credentials(TlsCredentials credentials) throws IOException {
        if (null == credentials) {
            return null;
        } else if (!(credentials instanceof TlsCredentialedSigner)) {
            throw new TlsFatalAlert((short)80);
        } else {
            return (TlsCredentialedSigner)credentials;
        }
    }

    static void negotiatedCipherSuite(SecurityParameters securityParameters, int cipherSuite) throws IOException {
        securityParameters.cipherSuite = cipherSuite;
        securityParameters.keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);
        int prfAlgorithm = getPRFAlgorithm(securityParameters, cipherSuite);
        securityParameters.prfAlgorithm = prfAlgorithm;
        switch(prfAlgorithm) {
            case 0:
            case 1:
                securityParameters.prfCryptoHashAlgorithm = -1;
                securityParameters.prfHashAlgorithm = -1;
                securityParameters.prfHashLength = -1;
                break;
            default:
                int prfCryptoHashAlgorithm = TlsCryptoUtils.getHashForPRF(prfAlgorithm);
                securityParameters.prfCryptoHashAlgorithm = prfCryptoHashAlgorithm;
                securityParameters.prfHashAlgorithm = getHashAlgorithmForPRFAlgorithm(prfAlgorithm);
                securityParameters.prfHashLength = TlsCryptoUtils.getHashOutputSize(prfCryptoHashAlgorithm);
        }

        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (isTLSv13(negotiatedVersion)) {
            securityParameters.verifyDataLength = securityParameters.getPRFHashLength();
        } else {
            securityParameters.verifyDataLength = negotiatedVersion.isSSL() ? 36 : 12;
        }

    }

    static void negotiatedVersion(SecurityParameters securityParameters) throws IOException {
        if (!isSignatureAlgorithmsExtensionAllowed(securityParameters.getNegotiatedVersion())) {
            securityParameters.clientSigAlgs = null;
            securityParameters.clientSigAlgsCert = null;
        } else {
            if (null == securityParameters.getClientSigAlgs()) {
                securityParameters.clientSigAlgs = getLegacySupportedSignatureAlgorithms();
            }

            if (null == securityParameters.getClientSigAlgsCert()) {
                securityParameters.clientSigAlgsCert = securityParameters.getClientSigAlgs();
            }

        }
    }

    static void negotiatedVersionDTLSClient(TlsClientContext clientContext, TlsClient client) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (!ProtocolVersion.isSupportedDTLSVersionClient(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            negotiatedVersion(securityParameters);
            client.notifyServerVersion(negotiatedVersion);
        }
    }

    static void negotiatedVersionDTLSServer(TlsServerContext serverContext) throws IOException {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (!ProtocolVersion.isSupportedDTLSVersionServer(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            negotiatedVersion(securityParameters);
        }
    }

    static void negotiatedVersionTLSClient(TlsClientContext clientContext, TlsClient client) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (!ProtocolVersion.isSupportedTLSVersionClient(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            negotiatedVersion(securityParameters);
            client.notifyServerVersion(negotiatedVersion);
        }
    }

    static void negotiatedVersionTLSServer(TlsServerContext serverContext) throws IOException {
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (!ProtocolVersion.isSupportedTLSVersionServer(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            negotiatedVersion(securityParameters);
        }
    }

    static TlsSecret deriveSecret(SecurityParameters securityParameters, TlsSecret secret, String label, byte[] transcriptHash) throws IOException {
        int prfCryptoHashAlgorithm = securityParameters.getPRFCryptoHashAlgorithm();
        int prfHashLength = securityParameters.getPRFHashLength();
        return deriveSecret(prfCryptoHashAlgorithm, prfHashLength, secret, label, transcriptHash);
    }

    static TlsSecret deriveSecret(int prfCryptoHashAlgorithm, int prfHashLength, TlsSecret secret, String label, byte[] transcriptHash) throws IOException {
        if (transcriptHash.length != prfHashLength) {
            throw new TlsFatalAlert((short)80);
        } else {
            return TlsCryptoUtils.hkdfExpandLabel(secret, prfCryptoHashAlgorithm, label, transcriptHash, prfHashLength);
        }
    }

    static TlsSecret getSessionMasterSecret(TlsCrypto crypto, TlsSecret masterSecret) {
        if (null != masterSecret) {
            synchronized(masterSecret) {
                if (masterSecret.isAlive()) {
                    return crypto.adoptSecret(masterSecret);
                }
            }
        }

        return null;
    }

    static boolean isPermittedExtensionType13(int handshakeType, int extensionType) {
        switch(extensionType) {
            case 0:
            case 1:
            case 10:
            case 14:
            case 15:
            case 16:
            case 19:
            case 20:
                switch(handshakeType) {
                    case 1:
                    case 8:
                        return true;
                    default:
                        return false;
                }
            case 2:
            case 3:
            case 4:
            case 6:
            case 7:
            case 8:
            case 9:
            case 11:
            case 12:
            case 17:
            case 22:
            case 23:
            case 24:
            case 25:
            case 26:
            case 28:
            case 29:
            case 30:
            case 31:
            case 32:
            case 33:
            case 34:
            case 35:
            case 36:
            case 37:
            case 38:
            case 39:
            case 40:
            case 46:
            default:
                return !ExtensionType.isRecognized(extensionType);
            case 5:
            case 18:
                switch(handshakeType) {
                    case 1:
                    case 11:
                    case 13:
                        return true;
                    default:
                        return false;
                }
            case 13:
            case 27:
            case 47:
            case 50:
                switch(handshakeType) {
                    case 1:
                    case 13:
                        return true;
                    default:
                        return false;
                }
            case 21:
            case 45:
            case 49:
                switch(handshakeType) {
                    case 1:
                        return true;
                    default:
                        return false;
                }
            case 41:
                switch(handshakeType) {
                    case 1:
                    case 2:
                        return true;
                    default:
                        return false;
                }
            case 42:
                switch(handshakeType) {
                    case 1:
                    case 4:
                    case 8:
                        return true;
                    default:
                        return false;
                }
            case 43:
            case 51:
                switch(handshakeType) {
                    case 1:
                    case 2:
                    case 6:
                        return true;
                    default:
                        return false;
                }
            case 44:
                switch(handshakeType) {
                    case 1:
                    case 6:
                        return true;
                    default:
                        return false;
                }
            case 48:
                switch(handshakeType) {
                    case 13:
                        return true;
                    default:
                        return false;
                }
        }
    }

    static void checkExtensionData13(Hashtable extensions, int handshakeType, short alertDescription) throws IOException {
        Enumeration e = extensions.keys();

        Integer extensionType;
        do {
            if (!e.hasMoreElements()) {
                return;
            }

            extensionType = (Integer)e.nextElement();
        } while(null != extensionType && isPermittedExtensionType13(handshakeType, extensionType));

        throw new TlsFatalAlert(alertDescription, "Invalid extension: " + ExtensionType.getText(extensionType));
    }

    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsEncryptor encryptor, OutputStream output) throws IOException {
        ProtocolVersion version = context.getRSAPreMasterSecretVersion();
        TlsSecret preMasterSecret = context.getCrypto().generateRSAPreMasterSecret(version);
        byte[] encryptedPreMasterSecret = preMasterSecret.encrypt(encryptor);
        writeEncryptedPMS(context, encryptedPreMasterSecret, output);
        return preMasterSecret;
    }

    static void addPreSharedKeyToClientExtensions(TlsPSK[] psks, Hashtable clientExtensions) throws IOException {
        Vector identities = new Vector(psks.length);

        for(int i = 0; i < psks.length; ++i) {
            TlsPSK psk = psks[i];
            identities.add(new PskIdentity(psk.getIdentity(), 0L));
        }

        TlsExtensionsUtils.addPreSharedKeyClientHello(clientExtensions, new OfferedPsks(identities));
    }

    static BindersConfig addPreSharedKeyToClientHello(TlsClientContext clientContext, TlsClient client, Hashtable clientExtensions, int[] offeredCipherSuites) throws IOException {
        if (!isTLSv13(clientContext.getClientVersion())) {
            return null;
        } else {
            TlsPSKExternal[] pskExternals = getPSKExternalsClient(client, offeredCipherSuites);
            if (null == pskExternals) {
                return null;
            } else {
                short[] pskKeyExchangeModes = client.getPskKeyExchangeModes();
                if (isNullOrEmpty(pskKeyExchangeModes)) {
                    throw new TlsFatalAlert((short)80, "External PSKs configured but no PskKeyExchangeMode available");
                } else {
                    TlsSecret[] pskEarlySecrets = getPSKEarlySecrets(clientContext.getCrypto(), pskExternals);
                    int bindersSize = OfferedPsks.getBindersSize(pskExternals);
                    addPreSharedKeyToClientExtensions(pskExternals, clientExtensions);
                    TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, pskKeyExchangeModes);
                    return new BindersConfig(pskExternals, pskKeyExchangeModes, pskEarlySecrets, bindersSize);
                }
            }
        }
    }

    static BindersConfig addPreSharedKeyToClientHelloRetry(TlsClientContext clientContext, BindersConfig clientBinders, Hashtable clientExtensions) throws IOException {
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        int prfAlgorithm = getPRFAlgorithm13(securityParameters.getCipherSuite());
        Vector pskIndices = getPSKIndices(clientBinders.psks, prfAlgorithm);
        if (pskIndices.isEmpty()) {
            return null;
        } else {
            BindersConfig result = clientBinders;
            int count = pskIndices.size();
            if (count < clientBinders.psks.length) {
                TlsPSK[] psks = new TlsPSK[count];
                TlsSecret[] earlySecrets = new TlsSecret[count];

                int bindersSize;
                for(bindersSize = 0; bindersSize < count; ++bindersSize) {
                    int j = (Integer)pskIndices.elementAt(bindersSize);
                    psks[bindersSize] = clientBinders.psks[j];
                    earlySecrets[bindersSize] = clientBinders.earlySecrets[j];
                }

                bindersSize = OfferedPsks.getBindersSize(psks);
                result = new BindersConfig(psks, clientBinders.pskKeyExchangeModes, earlySecrets, bindersSize);
            }

            addPreSharedKeyToClientExtensions(result.psks, clientExtensions);
            return result;
        }
    }

    static SelectedConfig selectPreSharedKey(TlsServerContext serverContext, TlsServer server, Hashtable clientHelloExtensions, HandshakeMessageInput clientHelloMessage, TlsHandshakeHash handshakeHash, boolean afterHelloRetryRequest) throws IOException {
        boolean handshakeHashUpdated = false;
        OfferedPsks offeredPsks = TlsExtensionsUtils.getPreSharedKeyClientHello(clientHelloExtensions);
        if (null != offeredPsks) {
            short[] pskKeyExchangeModes = TlsExtensionsUtils.getPSKKeyExchangeModesExtension(clientHelloExtensions);
            if (isNullOrEmpty(pskKeyExchangeModes)) {
                throw new TlsFatalAlert((short)109);
            }

            if (Arrays.contains(pskKeyExchangeModes, (short)1)) {
                TlsPSKExternal psk = server.getExternalPSK(offeredPsks.getIdentities());
                if (null != psk) {
                    int index = offeredPsks.getIndexOfIdentity(new PskIdentity(psk.getIdentity(), 0L));
                    if (index >= 0) {
                        byte[] binder = (byte[])((byte[])offeredPsks.getBinders().elementAt(index));
                        TlsCrypto crypto = serverContext.getCrypto();
                        TlsSecret earlySecret = getPSKEarlySecret(crypto, psk);
                        boolean isExternalPSK = true;
                        int pskCryptoHashAlgorithm = TlsCryptoUtils.getHashForPRF(psk.getPRFAlgorithm());
                        handshakeHashUpdated = true;
                        int bindersSize = offeredPsks.getBindersSize();
                        clientHelloMessage.updateHashPrefix(handshakeHash, bindersSize);
                        byte[] transcriptHash;
                        if (afterHelloRetryRequest) {
                            transcriptHash = handshakeHash.getFinalHash(pskCryptoHashAlgorithm);
                        } else {
                            TlsHash hash = crypto.createHash(pskCryptoHashAlgorithm);
                            handshakeHash.copyBufferTo(new TlsHashOutputStream(hash));
                            transcriptHash = hash.calculateHash();
                        }

                        clientHelloMessage.updateHashSuffix(handshakeHash, bindersSize);
                        byte[] calculatedBinder = calculatePSKBinder(crypto, isExternalPSK, pskCryptoHashAlgorithm, earlySecret, transcriptHash);
                        if (Arrays.constantTimeAreEqual(calculatedBinder, binder)) {
                            return new SelectedConfig(index, psk, pskKeyExchangeModes, earlySecret);
                        }
                    }
                }
            }
        }

        if (!handshakeHashUpdated) {
            clientHelloMessage.updateHash(handshakeHash);
        }

        return null;
    }

    static TlsSecret getPSKEarlySecret(TlsCrypto crypto, TlsPSK psk) {
        int cryptoHashAlgorithm = TlsCryptoUtils.getHashForPRF(psk.getPRFAlgorithm());
        return crypto.hkdfInit(cryptoHashAlgorithm).hkdfExtract(cryptoHashAlgorithm, psk.getKey());
    }

    static TlsSecret[] getPSKEarlySecrets(TlsCrypto crypto, TlsPSK[] psks) {
        int count = psks.length;
        TlsSecret[] earlySecrets = new TlsSecret[count];

        for(int i = 0; i < count; ++i) {
            earlySecrets[i] = getPSKEarlySecret(crypto, psks[i]);
        }

        return earlySecrets;
    }

    static TlsPSKExternal[] getPSKExternalsClient(TlsClient client, int[] offeredCipherSuites) throws IOException {
        Vector externalPSKs = client.getExternalPSKs();
        if (isNullOrEmpty(externalPSKs)) {
            return null;
        } else {
            int[] prfAlgorithms = getPRFAlgorithms13(offeredCipherSuites);
            int count = externalPSKs.size();
            TlsPSKExternal[] result = new TlsPSKExternal[count];

            for(int i = 0; i < count; ++i) {
                Object element = externalPSKs.elementAt(i);
                if (!(element instanceof TlsPSKExternal)) {
                    throw new TlsFatalAlert((short)80, "External PSKs element is not a TlsPSKExternal");
                }

                TlsPSKExternal pskExternal = (TlsPSKExternal)element;
                if (!Arrays.contains(prfAlgorithms, pskExternal.getPRFAlgorithm())) {
                    throw new TlsFatalAlert((short)80, "External PSK incompatible with offered cipher suites");
                }

                result[i] = pskExternal;
            }

            return result;
        }
    }

    static Vector getPSKIndices(TlsPSK[] psks, int prfAlgorithm) {
        Vector v = new Vector(psks.length);

        for(int i = 0; i < psks.length; ++i) {
            if (psks[i].getPRFAlgorithm() == prfAlgorithm) {
                v.add(Integers.valueOf(i));
            }
        }

        return v;
    }
}