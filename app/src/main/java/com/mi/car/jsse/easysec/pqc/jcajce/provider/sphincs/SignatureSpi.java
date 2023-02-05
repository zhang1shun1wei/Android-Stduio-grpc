package com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA3Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512tDigest;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCS256Signer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureSpi extends java.security.SignatureSpi {
    private Digest digest;
    private SecureRandom random;
    private SPHINCS256Signer signer;
    private final ASN1ObjectIdentifier treeDigest;

    protected SignatureSpi(Digest digest2, ASN1ObjectIdentifier treeDigest2, SPHINCS256Signer signer2) {
        this.digest = digest2;
        this.treeDigest = treeDigest2;
        this.signer = signer2;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof BCSphincs256PublicKey) {
            BCSphincs256PublicKey key = (BCSphincs256PublicKey) publicKey;
            if (!this.treeDigest.equals((ASN1Primitive) key.getTreeDigest())) {
                throw new InvalidKeyException("SPHINCS-256 signature for tree digest: " + key.getTreeDigest());
            }
            CipherParameters param = key.getKeyParams();
            this.digest.reset();
            this.signer.init(false, param);
            return;
        }
        throw new InvalidKeyException("unknown public key passed to SPHINCS-256");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitSign(PrivateKey privateKey, SecureRandom random2) throws InvalidKeyException {
        this.random = random2;
        engineInitSign(privateKey);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof BCSphincs256PrivateKey) {
            BCSphincs256PrivateKey key = (BCSphincs256PrivateKey) privateKey;
            if (!this.treeDigest.equals((ASN1Primitive) key.getTreeDigest())) {
                throw new InvalidKeyException("SPHINCS-256 signature for tree digest: " + key.getTreeDigest());
            }
            CipherParameters param = key.getKeyParams();
            this.digest.reset();
            this.signer.init(true, param);
            return;
        }
        throw new InvalidKeyException("unknown private key passed to SPHINCS-256");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.digest.update(b, off, len);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public byte[] engineSign() throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            return this.signer.generateSignature(hash);
        } catch (Exception e) {
            throw new SignatureException(e.toString());
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        return this.signer.verifySignature(hash, sigBytes);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    public static class withSha512 extends SignatureSpi {
        public withSha512() {
            super(new SHA512Digest(), NISTObjectIdentifiers.id_sha512_256, new SPHINCS256Signer(new SHA512tDigest(256), new SHA512Digest()));
        }
    }

    public static class withSha3_512 extends SignatureSpi {
        public withSha3_512() {
            super(new SHA3Digest(512), NISTObjectIdentifiers.id_sha3_256, new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512)));
        }
    }
}
