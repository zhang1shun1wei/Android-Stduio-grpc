package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.extend.jce.TeeKeyStoreSpi1;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class EasysecJsseProvider extends Provider {
    public static final String PROVIDER_NAME = "ESJSSE";
    private static final String JSSE_CONFIG_PROPERTY = "com.mi.car.jsse.easysec.jsse.config";
    private static final double PROVIDER_VERSION = 1.0013D;
    private static final String PROVIDER_INFO = "Bouncy Castle JSSE Provider Version 1.0.13";
    private Map<String, EasysecJsseProvider.BcJsseService> serviceMap;
    private Map<String, EngineCreator> creatorMap;
    private final boolean isInFipsMode;
    private static final Map<Map<String, String>, Map<String, String>> attributeMaps = new HashMap();

    public EasysecJsseProvider() {
        this(getPropertyValue("com.mi.car.jsse.easysec.jsse.config", "default"));
    }

    public EasysecJsseProvider(boolean fipsMode) {
        super("ESJSSE", 1.0013D, "Bouncy Castle JSSE Provider Version 1.0.13");
        this.serviceMap = new HashMap();
        this.creatorMap = new HashMap();
        this.isInFipsMode = this.configure(fipsMode, new JcaTlsCryptoProvider());
    }

    public EasysecJsseProvider(Provider provider) {
        this(false, provider);
    }

    public EasysecJsseProvider(boolean fipsMode, Provider provider) {
        super("ESJSSE", 1.0013D, "Bouncy Castle JSSE Provider Version 1.0.13");
        this.serviceMap = new HashMap();
        this.creatorMap = new HashMap();
        this.isInFipsMode = this.configure(fipsMode, (new JcaTlsCryptoProvider()).setProvider(provider));
    }

    public EasysecJsseProvider(String config) {
        super("ESJSSE", 1.0013D, "Bouncy Castle JSSE Provider Version 1.0.13");
        this.serviceMap = new HashMap();
        this.creatorMap = new HashMap();
        config = config.trim();
        boolean fipsMode = false;
        String cryptoName = config;
        int colonPos = config.indexOf(58);
        if (colonPos >= 0) {
            String first = config.substring(0, colonPos).trim();
            String second = config.substring(colonPos + 1).trim();
            fipsMode = first.equalsIgnoreCase("fips");
            cryptoName = second;
        }

        JcaTlsCryptoProvider cryptoProvider;
        try {
            cryptoProvider = this.createCryptoProvider(cryptoName);
        } catch (GeneralSecurityException var7) {
            throw new IllegalArgumentException("unable to set up JcaTlsCryptoProvider: " + var7.getMessage(), var7);
        }

        this.isInFipsMode = this.configure(fipsMode, cryptoProvider);
    }

    public EasysecJsseProvider(boolean fipsMode, JcaTlsCryptoProvider tlsCryptoProvider) {
        super("ESJSSE", 1.0013D, "Bouncy Castle JSSE Provider Version 1.0.13");
        this.serviceMap = new HashMap();
        this.creatorMap = new HashMap();
        this.isInFipsMode = this.configure(fipsMode, tlsCryptoProvider);
    }

    public Provider configure(String configArg) {
        return new EasysecJsseProvider(configArg);
    }

    private JcaTlsCryptoProvider createCryptoProvider(String cryptoName) throws GeneralSecurityException {
        if (cryptoName.equalsIgnoreCase("default")) {
            return new JcaTlsCryptoProvider();
        } else {
            Provider provider = Security.getProvider(cryptoName);
            if (provider != null) {
                return (new JcaTlsCryptoProvider()).setProvider(provider);
            } else {
                try {
                    Class<?> cryptoProviderClass = Class.forName(cryptoName);
                    Object cryptoProviderInstance = cryptoProviderClass.newInstance();
                    if (cryptoProviderInstance instanceof JcaTlsCryptoProvider) {
                        return (JcaTlsCryptoProvider)cryptoProviderInstance;
                    } else if (cryptoProviderInstance instanceof Provider) {
                        return (new JcaTlsCryptoProvider()).setProvider((Provider)cryptoProviderInstance);
                    } else {
                        throw new IllegalArgumentException("unrecognized class: " + cryptoName);
                    }
                } catch (ClassNotFoundException var5) {
                    throw new IllegalArgumentException("unable to find Provider/JcaTlsCryptoProvider class: " + cryptoName);
                } catch (InstantiationException var6) {
                    throw new IllegalArgumentException("unable to create Provider/JcaTlsCryptoProvider class '" + cryptoName + "': " + var6.getMessage(), var6);
                } catch (IllegalAccessException var7) {
                    throw new IllegalArgumentException("unable to create Provider/JcaTlsCryptoProvider class '" + cryptoName + "': " + var7.getMessage(), var7);
                }
            }
        }
    }

    private boolean configure(final boolean fipsMode, final JcaTlsCryptoProvider cryptoProvider) {
        this.addAlgorithmImplementation("KeyManagerFactory.X.509", "com.mi.car.jsse.easysec.jsse.provider.KeyManagerFactory", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvKeyManagerFactorySpi(fipsMode, cryptoProvider.getHelper());
            }
        });
        this.addAlias("Alg.Alias.KeyManagerFactory.X509", "X.509");
        this.addAlias("Alg.Alias.KeyManagerFactory.PKIX", "X.509");
        this.addAlgorithmImplementation("TrustManagerFactory.PKIX", "com.mi.car.jsse.easysec.jsse.provider.TrustManagerFactory", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvTrustManagerFactorySpi(fipsMode, cryptoProvider.getHelper());
            }
        });
        this.addAlias("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
        this.addAlias("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        this.addAlgorithmImplementation("SSLContext.TLS", "com.mi.car.jsse.easysec.jsse.provider.SSLContext.TLS", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvSSLContextSpi(fipsMode, cryptoProvider, (List)null);
            }
        });
        this.addAlgorithmImplementation("SSLContext.TLSV1", "com.mi.car.jsse.easysec.jsse.provider.SSLContext.TLSv1", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvSSLContextSpi(fipsMode, cryptoProvider, EasysecJsseProvider.specifyClientProtocols("TLSv1"));
            }
        });
        this.addAlgorithmImplementation("SSLContext.TLSV1.1", "com.mi.car.jsse.easysec.jsse.provider.SSLContext.TLSv1_1", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvSSLContextSpi(fipsMode, cryptoProvider, EasysecJsseProvider.specifyClientProtocols("TLSv1.1", "TLSv1"));
            }
        });
        this.addAlgorithmImplementation("SSLContext.TLSV1.2", "com.mi.car.jsse.easysec.jsse.provider.SSLContext.TLSv1_2", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvSSLContextSpi(fipsMode, cryptoProvider, EasysecJsseProvider.specifyClientProtocols("TLSv1.2", "TLSv1.1", "TLSv1"));
            }
        });
        this.addAlgorithmImplementation("SSLContext.TLSV1.3", "com.mi.car.jsse.easysec.jsse.provider.SSLContext.TLSv1_3", new EngineCreator() {
            public Object createInstance(Object constructorParameter) {
                return new ProvSSLContextSpi(fipsMode, cryptoProvider, EasysecJsseProvider.specifyClientProtocols("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"));
            }
        });
        this.addAlgorithmImplementation("SSLContext.DEFAULT", "com.mi.car.jsse.easysec.jsse.provider.SSLContext.Default", new EngineCreator() {
            public Object createInstance(Object constructorParameter) throws GeneralSecurityException {
                return new DefaultSSLContextSpi(fipsMode, cryptoProvider);
            }
        });
        this.addAlias("Alg.Alias.SSLContext.SSL", "TLS");
        this.addAlias("Alg.Alias.SSLContext.SSLV3", "TLSV1");
        this.addAlgorithmImplementation("KeyStore.TEEKS", "com.mi.car.jsse.easysec.extend.jce.KeyStore", (param) -> {
            return new TeeKeyStoreSpi1();
        });
        return fipsMode;
    }

    void addAttribute(String key, String attributeName, String attributeValue) {
        String attributeKey = key + " " + attributeName;
        if (this.containsKey(attributeKey)) {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        } else {
            this.put(attributeKey, attributeValue);
        }
    }

    void addAlgorithmImplementation(String key, String className, EngineCreator creator) {
        if (this.containsKey(key)) {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        } else {
            this.addAttribute(key, "ImplementedIn", "Software");
            this.put(key, className);
            this.creatorMap.put(className, creator);
        }
    }

    void addAlias(String key, String value) {
        if (this.containsKey(key)) {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        } else {
            this.put(key, value);
        }
    }

    public final synchronized Service getService(String type, String algorithm) {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);
        EasysecJsseProvider.BcJsseService service = (EasysecJsseProvider.BcJsseService)this.serviceMap.get(type + "." + upperCaseAlgName);
        if (service == null) {
            String aliasString = "Alg.Alias." + type + ".";
            String realName = (String)this.get(aliasString + upperCaseAlgName);
            if (realName == null) {
                realName = upperCaseAlgName;
            }

            String className = (String)this.get(type + "." + realName);
            if (className == null) {
                return null;
            }

            String attributeKeyStart = type + "." + upperCaseAlgName + " ";
            List<String> aliases = new ArrayList();
            Map<String, String> attributes = new HashMap();
            Iterator var11 = this.keySet().iterator();

            while(var11.hasNext()) {
                Object key = var11.next();
                String sKey = (String)key;
                if (sKey.startsWith(aliasString) && this.get(key).equals(algorithm)) {
                    aliases.add(sKey.substring(aliasString.length()));
                }

                if (sKey.startsWith(attributeKeyStart)) {
                    attributes.put(sKey.substring(attributeKeyStart.length()), (String)this.get(sKey));
                }
            }

            service = new EasysecJsseProvider.BcJsseService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), (EngineCreator)this.creatorMap.get(className));
            this.serviceMap.put(type + "." + upperCaseAlgName, service);
        }

        return service;
    }

    public final synchronized Set<Service> getServices() {
        Set<Service> serviceSet = super.getServices();
        Set<Service> bcServiceSet = new HashSet();
        Iterator var3 = serviceSet.iterator();

        while(var3.hasNext()) {
            Service service = (Service)var3.next();
            bcServiceSet.add(this.getService(service.getType(), service.getAlgorithm()));
        }

        return bcServiceSet;
    }

    private static Map<String, String> getAttributeMap(Map<String, String> attributeMap) {
        Map<String, String> attrMap = (Map)attributeMaps.get(attributeMap);
        if (attrMap != null) {
            return attrMap;
        } else {
            attributeMaps.put(attributeMap, attributeMap);
            return attributeMap;
        }
    }

    private static List<String> specifyClientProtocols(String... protocols) {
        return Arrays.asList(protocols);
    }

    public boolean isFipsMode() {
        return this.isInFipsMode;
    }

    private static String getPropertyValue(final String propertyName, final String defValue) {
        return (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                String v = Security.getProperty(propertyName);
                if (v != null) {
                    return v;
                } else {
                    v = System.getProperty(propertyName);
                    return v != null ? v : defValue;
                }
            }
        });
    }

    private static class BcJsseService extends Service {
        private final EngineCreator creator;

        public BcJsseService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes, EngineCreator creator) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.creator = creator;
        }

        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            try {
                Object instance = this.creator.createInstance(constructorParameter);
                if (instance == null) {
                    throw new NoSuchAlgorithmException("No such algorithm in FIPS approved mode: " + this.getAlgorithm());
                } else {
                    return instance;
                }
            } catch (NoSuchAlgorithmException var3) {
                throw var3;
            } catch (Exception var4) {
                throw new NoSuchAlgorithmException("Unable to invoke creator for " + this.getAlgorithm() + ": " + var4.getMessage(), var4);
            }
        }
    }
}
