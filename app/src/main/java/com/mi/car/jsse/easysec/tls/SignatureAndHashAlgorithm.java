package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SignatureAndHashAlgorithm {
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP256r1tls13_sha256 = create(2074);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP384r1tls13_sha384 = create(2075);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP512r1tls13_sha512 = create(2076);
    public static final SignatureAndHashAlgorithm ed25519 = create(2055);
    public static final SignatureAndHashAlgorithm ed448 = create(2056);
    public static final SignatureAndHashAlgorithm gostr34102012_256 = create((short)8, (short)64);
    public static final SignatureAndHashAlgorithm gostr34102012_512 = create((short)8, (short)65);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha256 = create(2052);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha384 = create(2053);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha512 = create(2054);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha256 = create(2057);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha384 = create(2058);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha512 = create(2059);
    protected final short hash;
    protected final short signature;

    public static SignatureAndHashAlgorithm getInstance(short hashAlgorithm, short signatureAlgorithm) {
        switch(hashAlgorithm) {
            case 8:
                return getInstanceIntrinsic(signatureAlgorithm);
            default:
                return create(hashAlgorithm, signatureAlgorithm);
        }
    }

    private static SignatureAndHashAlgorithm getInstanceIntrinsic(short signatureAlgorithm) {
        switch(signatureAlgorithm) {
            case 4:
                return rsa_pss_rsae_sha256;
            case 5:
                return rsa_pss_rsae_sha384;
            case 6:
                return rsa_pss_rsae_sha512;
            case 7:
                return ed25519;
            case 8:
                return ed448;
            case 9:
                return rsa_pss_pss_sha256;
            case 10:
                return rsa_pss_pss_sha384;
            case 11:
                return rsa_pss_pss_sha512;
            case 26:
                return ecdsa_brainpoolP256r1tls13_sha256;
            case 27:
                return ecdsa_brainpoolP384r1tls13_sha384;
            case 28:
                return ecdsa_brainpoolP512r1tls13_sha512;
            case 64:
                return gostr34102012_256;
            case 65:
                return gostr34102012_512;
            default:
                return create((short)8, signatureAlgorithm);
        }
    }

    private static SignatureAndHashAlgorithm create(int signatureScheme) {
        short hashAlgorithm = SignatureScheme.getHashAlgorithm(signatureScheme);
        short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme);
        return create(hashAlgorithm, signatureAlgorithm);
    }

    private static SignatureAndHashAlgorithm create(short hashAlgorithm, short signatureAlgorithm) {
        return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
    }

    public SignatureAndHashAlgorithm(short hash, short signature) {
        if ((hash & 255) != hash) {
            throw new IllegalArgumentException("'hash' should be a uint8");
        } else if ((signature & 255) != signature) {
            throw new IllegalArgumentException("'signature' should be a uint8");
        } else {
            this.hash = hash;
            this.signature = signature;
        }
    }

    public short getHash() {
        return this.hash;
    }

    public short getSignature() {
        return this.signature;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.getHash(), output);
        TlsUtils.writeUint8(this.getSignature(), output);
    }

    public static SignatureAndHashAlgorithm parse(InputStream input) throws IOException {
        short hash = TlsUtils.readUint8(input);
        short signature = TlsUtils.readUint8(input);
        return getInstance(hash, signature);
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof SignatureAndHashAlgorithm)) {
            return false;
        } else {
            SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm)obj;
            return other.getHash() == this.getHash() && other.getSignature() == this.getSignature();
        }
    }

    public int hashCode() {
        return this.getHash() << 16 | this.getSignature();
    }

    public String toString() {
        return "{" + HashAlgorithm.getText(this.hash) + "," + SignatureAlgorithm.getText(this.signature) + "}";
    }
}
