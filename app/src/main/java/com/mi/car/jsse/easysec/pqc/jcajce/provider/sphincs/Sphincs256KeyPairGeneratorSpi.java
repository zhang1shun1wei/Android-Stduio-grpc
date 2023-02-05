package com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.digests.SHA3Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512tDigest;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class Sphincs256KeyPairGeneratorSpi extends KeyPairGenerator {
    SPHINCS256KeyPairGenerator engine = new SPHINCS256KeyPairGenerator();
    boolean initialised = false;
    SPHINCS256KeyGenerationParameters param;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    ASN1ObjectIdentifier treeDigest = NISTObjectIdentifiers.id_sha512_256;

    public Sphincs256KeyPairGeneratorSpi() {
        super("SPHINCS256");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof SPHINCS256KeyGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a SPHINCS256KeyGenParameterSpec");
        }
        SPHINCS256KeyGenParameterSpec sphincsParams = (SPHINCS256KeyGenParameterSpec) params;
        if (sphincsParams.getTreeDigest().equals(SPHINCS256KeyGenParameterSpec.SHA512_256)) {
            this.treeDigest = NISTObjectIdentifiers.id_sha512_256;
            this.param = new SPHINCS256KeyGenerationParameters(random2, new SHA512tDigest(256));
        } else if (sphincsParams.getTreeDigest().equals("SHA3-256")) {
            this.treeDigest = NISTObjectIdentifiers.id_sha3_256;
            this.param = new SPHINCS256KeyGenerationParameters(random2, new SHA3Digest(256));
        }
        this.engine.init(this.param);
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new SPHINCS256KeyGenerationParameters(this.random, new SHA512tDigest(256));
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCSphincs256PublicKey(this.treeDigest, (SPHINCSPublicKeyParameters) pair.getPublic()), new BCSphincs256PrivateKey(this.treeDigest, (SPHINCSPrivateKeyParameters) pair.getPrivate()));
    }
}
