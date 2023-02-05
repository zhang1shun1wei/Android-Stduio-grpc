//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce.provider.asymmetric;

import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.misc.MiscObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jcajce.CompositePrivateKey;
import com.mi.car.jsse.easysec.jcajce.CompositePublicKey;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class COMPOSITE {
    private static final String PREFIX = "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.COMPOSITE";
    private static final Map<String, String> compositeAttributes = new HashMap();
    private static AsymmetricKeyInfoConverter baseConverter;

    public COMPOSITE() {
    }

    static {
        compositeAttributes.put("SupportedKeyClasses", "com.mi.car.jsse.easysec.jcajce.CompositePublicKey|com.mi.car.jsse.easysec.jcajce.CompositePrivateKey");
        compositeAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.COMPOSITE", "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.COMPOSITE$KeyFactory");
            provider.addAlgorithm("KeyFactory." + MiscObjectIdentifiers.id_alg_composite, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.COMPOSITE$KeyFactory");
            provider.addAlgorithm("KeyFactory.OID." + MiscObjectIdentifiers.id_alg_composite, "com.mi.car.jsse.easysec.jcajce.provider.asymmetric.COMPOSITE$KeyFactory");
            COMPOSITE.baseConverter = new COMPOSITE.CompositeKeyInfoConverter(provider);
            provider.addKeyInfoConverter(MiscObjectIdentifiers.id_alg_composite, COMPOSITE.baseConverter);
        }
    }

    private static class CompositeKeyInfoConverter implements AsymmetricKeyInfoConverter {
        private final ConfigurableProvider provider;

        public CompositeKeyInfoConverter(ConfigurableProvider provider) {
            this.provider = provider;
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(keyInfo.getPrivateKey().getOctets());
            PrivateKey[] privKeys = new PrivateKey[keySeq.size()];

            for(int i = 0; i != keySeq.size(); ++i) {
                PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(keySeq.getObjectAt(i));
                privKeys[i] = this.provider.getKeyInfoConverter(privInfo.getPrivateKeyAlgorithm().getAlgorithm()).generatePrivate(privInfo);
            }

            return new CompositePrivateKey(privKeys);
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(keyInfo.getPublicKeyData().getBytes());
            PublicKey[] pubKeys = new PublicKey[keySeq.size()];

            for(int i = 0; i != keySeq.size(); ++i) {
                SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(keySeq.getObjectAt(i));
                pubKeys[i] = this.provider.getKeyInfoConverter(pubInfo.getAlgorithm().getAlgorithm()).generatePublic(pubInfo);
            }

            return new CompositePublicKey(pubKeys);
        }
    }

    public static class KeyFactory extends BaseKeyFactorySpi {
        public KeyFactory() {
        }

        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            try {
                if (key instanceof PrivateKey) {
                    return this.generatePrivate(PrivateKeyInfo.getInstance(key.getEncoded()));
                }

                if (key instanceof PublicKey) {
                    return this.generatePublic(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
                }
            } catch (IOException var3) {
                throw new InvalidKeyException("key could not be parsed: " + var3.getMessage());
            }

            throw new InvalidKeyException("key not recognized");
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
            return COMPOSITE.baseConverter.generatePrivate(keyInfo);
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
            return COMPOSITE.baseConverter.generatePublic(keyInfo);
        }
    }
}