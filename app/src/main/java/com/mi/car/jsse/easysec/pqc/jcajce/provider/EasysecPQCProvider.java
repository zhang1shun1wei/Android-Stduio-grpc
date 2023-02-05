package com.mi.car.jsse.easysec.pqc.jcajce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.config.ProviderConfiguration;
import com.mi.car.jsse.easysec.jcajce.provider.util.AlgorithmProvider;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricKeyInfoConverter;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class EasysecPQCProvider extends Provider implements ConfigurableProvider {
    private static final String[] ALGORITHMS = {"Rainbow", "McEliece", "SPHINCS", "LMS", "NH", "XMSS", "SPHINCSPlus", "CMCE", "Frodo", "SABER"};
    private static final String ALGORITHM_PACKAGE = "com.mi.car.jsse.easysec.pqc.jcajce.provider.";
    public static final ProviderConfiguration CONFIGURATION = null;
    public static String PROVIDER_NAME = "ESPQC";
    private static String info = "BouncyCastle Post-Quantum Security Provider v1.71";
    private static final Map keyInfoConverters = new HashMap();

    public EasysecPQCProvider() {
        super(PROVIDER_NAME, 1.71d, info);
        AccessController.doPrivileged(new PrivilegedAction() {
            /* class com.mi.car.jsse.easysec.pqc.jcajce.provider.EasysecPQCProvider.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public Object run() {
                EasysecPQCProvider.this.setup();
                return null;
            }
        });
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private void setup() {
        loadAlgorithms(ALGORITHM_PACKAGE, ALGORITHMS);
    }

    private void loadAlgorithms(String packageName, String[] names) {
        for (int i = 0; i != names.length; i++) {
            Class clazz = loadClass(EasysecPQCProvider.class, packageName + names[i] + "$Mappings");
            if (clazz != null) {
                try {
                    ((AlgorithmProvider) clazz.newInstance()).configure(this);
                } catch (Exception e) {
                    throw new InternalError("cannot create instance of " + packageName + names[i] + "$Mappings : " + e);
                }
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public void setParameter(String parameterName, Object parameter) {
        synchronized (CONFIGURATION) {
        }
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public boolean hasAlgorithm(String type, String name) {
        return containsKey(new StringBuilder().append(type).append(".").append(name).toString()) || containsKey(new StringBuilder().append("Alg.Alias.").append(type).append(".").append(name).toString());
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public void addAlgorithm(String key, String value) {
        if (containsKey(key)) {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }
        put(key, value);
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className) {
        if (!containsKey(type + "." + className)) {
            throw new IllegalStateException("primary key (" + type + "." + className + ") not found");
        }
        addAlgorithm(type + "." + oid, className);
        addAlgorithm(type + ".OID." + oid, className);
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter) {
        synchronized (keyInfoConverters) {
            keyInfoConverters.put(oid, keyInfoConverter);
        }
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public AsymmetricKeyInfoConverter getKeyInfoConverter(ASN1ObjectIdentifier oid) {
        return (AsymmetricKeyInfoConverter) keyInfoConverters.get(oid);
    }

    @Override // com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider
    public void addAttributes(String key, Map<String, String> attributeMap) {
        for (String attributeName : attributeMap.keySet()) {
            String attributeKey = key + " " + attributeName;
            if (containsKey(attributeKey)) {
                throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
            }
            put(attributeKey, attributeMap.get(attributeName));
        }
    }

    private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm) {
        AsymmetricKeyInfoConverter asymmetricKeyInfoConverter;
        synchronized (keyInfoConverters) {
            asymmetricKeyInfoConverter = (AsymmetricKeyInfoConverter) keyInfoConverters.get(algorithm);
        }
        return asymmetricKeyInfoConverter;
    }

    public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());
        if (converter == null) {
            return null;
        }
        return converter.generatePublic(publicKeyInfo);
    }

    public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
        if (converter == null) {
            return null;
        }
        return converter.generatePrivate(privateKeyInfo);
    }

    static Class loadClass(Class sourceClass, final String className) {
        try {
            ClassLoader loader = sourceClass.getClassLoader();
            if (loader != null) {
                return loader.loadClass(className);
            }
            return (Class) AccessController.doPrivileged(new PrivilegedAction() {
                /* class com.mi.car.jsse.easysec.pqc.jcajce.provider.EasysecPQCProvider.AnonymousClass2 */

                @Override // java.security.PrivilegedAction
                public Object run() {
                    try {
                        return Class.forName(className);
                    } catch (Exception e) {
                        return null;
                    }
                }
            });
        } catch (ClassNotFoundException e) {
            return null;
        }
    }
}
