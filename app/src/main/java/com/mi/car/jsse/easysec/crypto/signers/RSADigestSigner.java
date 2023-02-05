package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.encodings.PKCS1Encoding;
import com.mi.car.jsse.easysec.crypto.engines.RSABlindedEngine;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.util.Hashtable;

public class RSADigestSigner implements Signer {
    private static final Hashtable oidMap = new Hashtable();
    private final AlgorithmIdentifier algId;
    private final Digest digest;
    private boolean forSigning;
    private final AsymmetricBlockCipher rsaEngine;

    static {
        oidMap.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
        oidMap.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
        oidMap.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);
        oidMap.put(McElieceCCA2KeyGenParameterSpec.SHA1, X509ObjectIdentifiers.id_SHA1);
        oidMap.put(McElieceCCA2KeyGenParameterSpec.SHA224, NISTObjectIdentifiers.id_sha224);
        oidMap.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        oidMap.put(McElieceCCA2KeyGenParameterSpec.SHA384, NISTObjectIdentifiers.id_sha384);
        oidMap.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        oidMap.put("SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        oidMap.put(SPHINCSKeyParameters.SHA512_256, NISTObjectIdentifiers.id_sha512_256);
        oidMap.put("SHA3-224", NISTObjectIdentifiers.id_sha3_224);
        oidMap.put("SHA3-256", NISTObjectIdentifiers.id_sha3_256);
        oidMap.put("SHA3-384", NISTObjectIdentifiers.id_sha3_384);
        oidMap.put("SHA3-512", NISTObjectIdentifiers.id_sha3_512);
        oidMap.put("MD2", PKCSObjectIdentifiers.md2);
        oidMap.put("MD4", PKCSObjectIdentifiers.md4);
        oidMap.put("MD5", PKCSObjectIdentifiers.md5);
    }

    public RSADigestSigner(Digest digest2) {
        this(digest2, (ASN1ObjectIdentifier) oidMap.get(digest2.getAlgorithmName()));
    }

    public RSADigestSigner(Digest digest2, ASN1ObjectIdentifier digestOid) {
        this.rsaEngine = new PKCS1Encoding(new RSABlindedEngine());
        this.digest = digest2;
        if (digestOid != null) {
            this.algId = new AlgorithmIdentifier(digestOid, DERNull.INSTANCE);
        } else {
            this.algId = null;
        }
    }

    public String getAlgorithmName() {
        return this.digest.getAlgorithmName() + "withRSA";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning2, CipherParameters parameters) {
        AsymmetricKeyParameter k;
        this.forSigning = forSigning2;
        if (parameters instanceof ParametersWithRandom) {
            k = (AsymmetricKeyParameter) ((ParametersWithRandom) parameters).getParameters();
        } else {
            k = (AsymmetricKeyParameter) parameters;
        }
        if (forSigning2 && !k.isPrivate()) {
            throw new IllegalArgumentException("signing requires private key");
        } else if (forSigning2 || !k.isPrivate()) {
            reset();
            this.rsaEngine.init(forSigning2, parameters);
        } else {
            throw new IllegalArgumentException("verification requires public key");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte input) {
        this.digest.update(input);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] input, int inOff, int length) {
        this.digest.update(input, inOff, length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        if (!this.forSigning) {
            throw new IllegalStateException("RSADigestSigner not initialised for signature generation.");
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            byte[] data = derEncode(hash);
            return this.rsaEngine.processBlock(data, 0, data.length);
        } catch (IOException e) {
            throw new CryptoException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        boolean z = true;
        if (this.forSigning) {
            throw new IllegalStateException("RSADigestSigner not initialised for verification");
        }
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            byte[] sig = this.rsaEngine.processBlock(signature, 0, signature.length);
            byte[] expected = derEncode(hash);
            if (sig.length == expected.length) {
                return Arrays.constantTimeAreEqual(sig, expected);
            }
            if (sig.length == expected.length - 2) {
                int sigOffset = (sig.length - hash.length) - 2;
                int expectedOffset = (expected.length - hash.length) - 2;
                expected[1] = (byte) (expected[1] - 2);
                expected[3] = (byte) (expected[3] - 2);
                int nonEqual = 0;
                for (int i = 0; i < hash.length; i++) {
                    nonEqual |= sig[sigOffset + i] ^ expected[expectedOffset + i];
                }
                for (int i2 = 0; i2 < sigOffset; i2++) {
                    nonEqual |= sig[i2] ^ expected[i2];
                }
                if (nonEqual != 0) {
                    z = false;
                }
                return z;
            }
            Arrays.constantTimeAreEqual(expected, expected);
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.digest.reset();
    }

    private byte[] derEncode(byte[] hash) throws IOException {
        if (this.algId != null) {
            return new DigestInfo(this.algId, hash).getEncoded(ASN1Encoding.DER);
        }
        try {
            DigestInfo.getInstance(hash);
            return hash;
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed DigestInfo for NONEwithRSA hash: " + e.getMessage());
        }
    }
}
