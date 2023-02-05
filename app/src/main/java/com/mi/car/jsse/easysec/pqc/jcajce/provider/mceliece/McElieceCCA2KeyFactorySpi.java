package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class McElieceCCA2KeyFactorySpi extends KeyFactorySpi implements AsymmetricKeyInfoConverter {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

    /* access modifiers changed from: protected */
    @Override // java.security.KeyFactorySpi
    public PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            try {
                SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(((X509EncodedKeySpec) keySpec).getEncoded()));
                try {
                    if (PQCObjectIdentifiers.mcElieceCca2.equals((ASN1Primitive) pki.getAlgorithm().getAlgorithm())) {
                        McElieceCCA2PublicKey key = McElieceCCA2PublicKey.getInstance(pki.parsePublicKey());
                        return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeyParameters(key.getN(), key.getT(), key.getG(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
                    }
                    throw new InvalidKeySpecException("Unable to recognise OID in McEliece private key");
                } catch (IOException cce) {
                    throw new InvalidKeySpecException("Unable to decode X509EncodedKeySpec: " + cce.getMessage());
                }
            } catch (IOException e) {
                throw new InvalidKeySpecException(e.toString());
            }
        } else {
            throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass() + ".");
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.KeyFactorySpi
    public PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            try {
                PrivateKeyInfo pki = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(((PKCS8EncodedKeySpec) keySpec).getEncoded()));
                try {
                    if (PQCObjectIdentifiers.mcElieceCca2.equals((ASN1Primitive) pki.getPrivateKeyAlgorithm().getAlgorithm())) {
                        McElieceCCA2PrivateKey key = McElieceCCA2PrivateKey.getInstance(pki.parsePrivateKey());
                        return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
                    }
                    throw new InvalidKeySpecException("Unable to recognise OID in McEliece public key");
                } catch (IOException e) {
                    throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec.");
                }
            } catch (IOException e2) {
                throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec: " + e2);
            }
        } else {
            throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass() + ".");
        }
    }

    public KeySpec getKeySpec(Key key, Class keySpec) throws InvalidKeySpecException {
        if (key instanceof BCMcElieceCCA2PrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        } else if (!(key instanceof BCMcElieceCCA2PublicKey)) {
            throw new InvalidKeySpecException("Unsupported key type: " + key.getClass() + ".");
        } else if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            return new X509EncodedKeySpec(key.getEncoded());
        }
        throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
    }

    public Key translateKey(Key key) throws InvalidKeyException {
        if ((key instanceof BCMcElieceCCA2PrivateKey) || (key instanceof BCMcElieceCCA2PublicKey)) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type.");
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PublicKey generatePublic(SubjectPublicKeyInfo pki) throws IOException {
        McElieceCCA2PublicKey key = McElieceCCA2PublicKey.getInstance(pki.parsePublicKey());
        return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeyParameters(key.getN(), key.getT(), key.getG(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PrivateKey generatePrivate(PrivateKeyInfo pki) throws IOException {
        McElieceCCA2PrivateKey key = McElieceCCA2PrivateKey.getInstance(pki.parsePrivateKey().toASN1Primitive());
        return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP(), null));
    }

    /* access modifiers changed from: protected */
    @Override // java.security.KeyFactorySpi
    public KeySpec engineGetKeySpec(Key key, Class tClass) throws InvalidKeySpecException {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.KeyFactorySpi
    public Key engineTranslateKey(Key key) throws InvalidKeyException {
        return null;
    }
}
