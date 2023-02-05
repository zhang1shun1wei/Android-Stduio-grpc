package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.util.DefaultJcaJceHelper;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jcajce.util.NamedJcaJceHelper;
import com.mi.car.jsse.easysec.jcajce.util.ProviderJcaJceHelper;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoProvider;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

public class JcaTlsCryptoProvider implements TlsCryptoProvider {
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcaTlsCryptoProvider() {
    }

    public JcaTlsCryptoProvider setProvider(Provider provider) {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }

    public JcaTlsCryptoProvider setProvider(String providerName) {
        this.helper = new NamedJcaJceHelper(providerName);
        return this;
    }

    public JcaTlsCrypto create(SecureRandom random) {
        try {
            if (random == null) {
                if (this.helper instanceof DefaultJcaJceHelper) {
                    random = SecureRandom.getInstance("DEFAULT");
                } else {
                    random = SecureRandom.getInstance("DEFAULT", this.helper.createDigest("SHA-512").getProvider());
                }
            }

            return this.create(random, new JcaTlsCryptoProvider.NonceEntropySource(this.helper, random));
        } catch (GeneralSecurityException var3) {
            throw Exceptions.illegalStateException("unable to create JcaTlsCrypto: " + var3.getMessage(), var3);
        }
    }

    public JcaTlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom) {
        return new JcaTlsCrypto(this.helper, keyRandom, nonceRandom);
    }

    public JcaJceHelper getHelper() {
        return this.helper;
    }

    private static class NonceEntropySource extends SecureRandom {
        NonceEntropySource(JcaJceHelper helper, SecureRandom random) throws GeneralSecurityException {
            super(new JcaTlsCryptoProvider.NonceEntropySource.NonceEntropySourceSpi(random, helper.createDigest("SHA-512")), random.getProvider());
        }

        private static class NonceEntropySourceSpi extends SecureRandomSpi {
            private final SecureRandom source;
            private final MessageDigest digest;
            private final byte[] seed;
            private final byte[] state;

            NonceEntropySourceSpi(SecureRandom source, MessageDigest digest) {
                this.source = source;
                this.digest = digest;
                this.seed = source.generateSeed(digest.getDigestLength());
                this.state = new byte[this.seed.length];
            }

            protected void engineSetSeed(byte[] bytes) {
                synchronized(this.digest) {
                    this.runDigest(this.seed, bytes, this.seed);
                }
            }

            protected void engineNextBytes(byte[] bytes) {
                synchronized(this.digest) {
                    int stateOff = this.state.length;

                    for(int i = 0; i != bytes.length; ++i) {
                        if (stateOff == this.state.length) {
                            this.source.nextBytes(this.state);
                            this.runDigest(this.seed, this.state, this.state);
                            stateOff = 0;
                        }

                        bytes[i] = this.state[stateOff++];
                    }

                }
            }

            protected byte[] engineGenerateSeed(int seedLen) {
                return this.source.generateSeed(seedLen);
            }

            private void runDigest(byte[] x, byte[] y, byte[] z) {
                this.digest.update(x);
                this.digest.update(y);

                try {
                    this.digest.digest(z, 0, z.length);
                } catch (DigestException var5) {
                    throw Exceptions.illegalStateException("unable to generate nonce data: " + var5.getMessage(), var5);
                }
            }
        }
    }
}
