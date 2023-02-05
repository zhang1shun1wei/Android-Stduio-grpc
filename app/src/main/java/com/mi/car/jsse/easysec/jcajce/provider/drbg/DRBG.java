package com.mi.car.jsse.easysec.jcajce.provider.drbg;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.prng.EntropySource;
import com.mi.car.jsse.easysec.crypto.prng.EntropySourceProvider;
import com.mi.car.jsse.easysec.crypto.prng.SP800SecureRandom;
import com.mi.car.jsse.easysec.crypto.prng.SP800SecureRandomBuilder;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.ClassUtil;
import com.mi.car.jsse.easysec.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import com.mi.car.jsse.easysec.util.Properties;
import com.mi.car.jsse.easysec.util.Strings;

/**
 * <b>DRBG Configuration</b><br/>
 * <p>
 * com.mi.car.jsse.easysec.drbg.gather_pause_secs - is to stop the entropy collection thread from grabbing all
 * available entropy on the system. The original motivation for the hybrid infrastructure was virtual machines
 * sometimes produce very few bits of entropy a second, the original approach (which "worked" at least for BC) was
 * to just read on the second thread and allow things to progress around it, but it did tend to hog the system
 * if other processes were using /dev/random. By default the thread will pause for 5 seconds between 64 bit reads,
 * increasing this time will reduce the demands on the system entropy pool. Ideally the pause will be set to large
 * enough to allow everyone to work together, but small enough to ensure the provider's DRBG is being regularly
 * reseeded.
 * </p>
 * <p>
 * com.mi.car.jsse.easysec.drbg.entropysource - is the class name for an implementation of EntropySourceProvider.
 * For example, one could be provided which just reads directly from /dev/random and the extra infrastructure used here
 * could be avoided.
 * </p>
 */
public class DRBG
{
    private static final Logger LOG = Logger.getLogger(DRBG.class.getName());

    private static final String PREFIX = DRBG.class.getName();

    // {"Provider class name","SecureRandomSpi class name"}
    private static final String[][] initialEntropySourceNames = new String[][]
        {
            // Normal JVM
            {"sun.security.provider.Sun", "sun.security.provider.SecureRandom"},
            // Apache harmony
            {"org.apache.harmony.security.provider.crypto.CryptoProvider", "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl"},
            // Android.
            {"com.android.org.conscrypt.OpenSSLProvider", "com.android.org.conscrypt.OpenSSLRandom"},
            {"org.conscrypt.OpenSSLProvider", "org.conscrypt.OpenSSLRandom"},
        };

    // Cascade through providers looking for match.
    private final static Object[] findSource()
    {
        for (int t = 0; t < initialEntropySourceNames.length; t++)
        {
            String[] pair = initialEntropySourceNames[t];
            try
            {
                Object[] r = new Object[]{Class.forName(pair[0]).newInstance(), Class.forName(pair[1]).newInstance()};

                return r;
            }
            catch (Throwable ex)
            {
                continue;
            }
        }

        return null;
    }

    private static EntropyDaemon entropyDaemon = null;
    private static Thread entropyThread = null;

    static
    {
        entropyDaemon = new EntropyDaemon();
        entropyThread = new Thread(entropyDaemon, "BC Entropy Daemon");
        entropyThread.setDaemon(true);
        entropyThread.start();
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecureRandom.DEFAULT", PREFIX + "$Default");
            provider.addAlgorithm("SecureRandom.NONCEANDIV", PREFIX + "$NonceAndIV");
        }
    }

    public static class Default
        extends SecureRandomSpi
    {
        private static final SecureRandom random = createBaseRandom(true);

        public Default()
        {
        }

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return random.generateSeed(numBytes);
        }
    }

    public static class NonceAndIV
        extends SecureRandomSpi
    {
        private static final SecureRandom random = createBaseRandom(false);

        public NonceAndIV()
        {
        }

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return random.generateSeed(numBytes);
        }
    }

    private static SecureRandom createBaseRandom(boolean isPredictionResistant)
    {
        if (Properties.getPropertyValue("com.mi.car.jsse.easysec.drbg.entropysource") != null)
        {
            EntropySourceProvider entropyProvider = createEntropySource();

            EntropySource initSource = entropyProvider.get(16 * 8);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(initSource.getEntropy())
                : generateNonceIVPersonalizationString(initSource.getEntropy());

            return new SP800SecureRandomBuilder(entropyProvider)
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), initSource.getEntropy(), isPredictionResistant);
        }
        else
        {
            EntropySource source = new HybridEntropySource(entropyDaemon, 256);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(source.getEntropy())
                : generateNonceIVPersonalizationString(source.getEntropy());

            return new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                @Override
                public EntropySource get(int bitsRequired)
                {
                    return new HybridEntropySource(entropyDaemon, bitsRequired);
                }
            })
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), source.getEntropy(), isPredictionResistant);
        }
    }

    // unfortunately new SecureRandom() can cause a regress and it's the only reliable way of getting access
    // to the JVM's seed generator.
    private static EntropySourceProvider createInitialEntropySource()
    {
        boolean hasGetInstanceStrong = AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                try
                {
                    Class def = SecureRandom.class;

                    return def.getMethod("getInstanceStrong") != null;
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        });

        if (hasGetInstanceStrong)
        {
            SecureRandom strong = AccessController.doPrivileged(new PrivilegedAction<SecureRandom>()
            {
                public SecureRandom run()
                {
                    try
                    {
                        return (SecureRandom)SecureRandom.class.getMethod("getInstanceStrong").invoke(null);
                    }
                    catch (Exception e)
                    {
                        return new CoreSecureRandom(findSource());
                    }
                }
            });

            return new IncrementalEntropySourceProvider(strong, true);
        }
        else
        {
            return new IncrementalEntropySourceProvider(new CoreSecureRandom(findSource()), true);
        }
    }

    private static EntropySourceProvider createCoreEntropySourceProvider()
    {
        if (Security.getProperty("securerandom.source") == null)
        {
            return createInitialEntropySource();
        }
        else
        {
            try
            {
                String source = Security.getProperty("securerandom.source");

                return new URLSeededEntropySourceProvider(new URL(source));
            }
            catch (Exception e)
            {
                return createInitialEntropySource();
            }
        }
    }

    private static EntropySourceProvider createEntropySource()
    {
        final String sourceClass = Properties.getPropertyValue("com.mi.car.jsse.easysec.drbg.entropysource");

        return AccessController.doPrivileged(new PrivilegedAction<EntropySourceProvider>()
        {
            public EntropySourceProvider run()
            {
                try
                {
                    Class clazz = ClassUtil.loadClass(DRBG.class, sourceClass);

                    return (EntropySourceProvider)clazz.newInstance();
                }
                catch (Exception e)
                {
                    throw new IllegalStateException("entropy source " + sourceClass + " not created: " + e.getMessage(), e);
                }
            }
        });
    }

    private static byte[] generateDefaultPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), seed,
            Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), seed,
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }

    private static class EntropyDaemon
        implements Runnable
    {
        private final ConcurrentLinkedQueue<Runnable> tasks = new ConcurrentLinkedQueue<Runnable>();

        void addTask(Runnable task)
        {
            tasks.add(task);
        }

        @Override
        public void run()
        {
            while (!Thread.currentThread().isInterrupted())
            {
                Runnable task = tasks.poll();

                if (task != null)
                {
                    try
                    {
                        task.run();
                    }
                    catch (Throwable e)
                    {
                        // ignore
                    }
                }
                else
                {
                    try
                    {
                        Thread.sleep(5000);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                    }
                }
            }

            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("entropy thread interrupted - exiting");
            }
        }
    }

    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom(Object[] initialEntropySourceAndSpi)
        {
            super((SecureRandomSpi)initialEntropySourceAndSpi[1], (Provider)initialEntropySourceAndSpi[0]);
        }
    }

    private static long getPause()
    {
        String pauseSetting = Properties.getPropertyValue("com.mi.car.jsse.easysec.drbg.gather_pause_secs");

        if (pauseSetting != null)
        {
            try
            {
                return Long.parseLong(pauseSetting) * 1000;
            }
            catch (Exception e)
            {
                return 5000;
            }
        }
        return 5000;
    }

    private static void sleep(long ms)
            throws InterruptedException
    {
        if (ms != 0)
        {
            Thread.sleep(ms);
        }
    }

    private static class URLSeededEntropySourceProvider
        implements EntropySourceProvider
    {
        private final InputStream seedStream;

        URLSeededEntropySourceProvider(final URL url)
        {
            this.seedStream = AccessController.doPrivileged(new PrivilegedAction<InputStream>()
            {
                public InputStream run()
                {
                    try
                    {
                        return url.openStream();
                    }
                    catch (IOException e)
                    {
                        throw new IllegalStateException("unable to open random source");
                    }
                }
            });
        }

        private int privilegedRead(final byte[] data, final int off, final int len)
        {
            return AccessController.doPrivileged(new PrivilegedAction<Integer>()
            {
                public Integer run()
                {
                    try
                    {
                        return seedStream.read(data, off, len);
                    }
                    catch (IOException e)
                    {
                        throw new InternalError("unable to read random source");
                    }
                }
            });
        }

        public EntropySource get(final int bitsRequired)
        {
            return new IncrementalEntropySource()
            {
                private final int numBytes = (bitsRequired + 7) / 8;

                public boolean isPredictionResistant()
                {
                    return true;
                }

                public byte[] getEntropy()
                {
                    try
                    {
                        return getEntropy(0);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                    }
                }

                public byte[] getEntropy(long pause)
                    throws InterruptedException
                {
                    byte[] data = new byte[numBytes];

                    int off = 0;
                    int len;

                    while (off != data.length && (len = privilegedRead(data, off, data.length - off)) > -1)
                    {
                        off += len;
                        sleep(pause);
                    }

                    if (off != data.length)
                    {
                        throw new InternalError("unable to fully read random source");
                    }

                    return data;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }

    private interface IncrementalEntropySource
        extends EntropySource
    {
        /**
         * Pause allows for a gap between fetches. We only want this after we've initialised.
         * @param pause time in milliseconds to pause in build up seed.
         * @return the resulting seed
         */
        byte[] getEntropy(long pause)
            throws InterruptedException;
    }

    private static class HybridEntropySource
        implements EntropySource
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);

        private final SP800SecureRandom drbg;
        private final SignallingEntropySource entropySource;
        private final int bytesRequired;
        private final byte[] additionalInput = Pack.longToBigEndian(System.currentTimeMillis());

        HybridEntropySource(final EntropyDaemon entropyDaemon, final int bitsRequired)
        {
            EntropySourceProvider entropyProvider = createCoreEntropySourceProvider();
            bytesRequired = (bitsRequired + 7) / 8;
            // remember for the seed generator we need the correct security strength for SHA-512
            entropySource = new SignallingEntropySource(entropyDaemon, seedAvailable, entropyProvider, 256);
            drbg = new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                public EntropySource get(final int bitsRequired)
                {
                    return entropySource;
                }
            })
            .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
            .buildHMAC(new HMac(new SHA512Digest()), entropySource.getEntropy(), false);     // 32 byte nonce
        }

        @Override
        public boolean isPredictionResistant()
        {
            return true;
        }

        @Override
        public byte[] getEntropy()
        {
            byte[] entropy = new byte[bytesRequired];

            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed(additionalInput);
                }
                else
                {
                    entropySource.schedule();
                }
            }

            drbg.nextBytes(entropy);

            return entropy;
        }

        @Override
        public int entropySize()
        {
            return bytesRequired * 8;
        }

        private class SignallingEntropySource
            implements IncrementalEntropySource
        {
            private final EntropyDaemon entropyDaemon;
            private final AtomicBoolean seedAvailable;
            private final IncrementalEntropySource entropySource;
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);
            private final long pause;

            SignallingEntropySource(EntropyDaemon entropyDaemon, AtomicBoolean seedAvailable, EntropySourceProvider baseRandom, int bitsRequired)
            {
                this.entropyDaemon = entropyDaemon;
                this.seedAvailable = seedAvailable;
                this.entropySource = (IncrementalEntropySource)baseRandom.get(bitsRequired);
                this.byteLength = (bitsRequired + 7) / 8;
                this.pause = getPause();
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                try
                {
                    return getEntropy(0);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                }
            }
            
            public byte[] getEntropy(long pause)
                throws InterruptedException
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = entropySource.getEntropy(pause);
                }
                else
                {
                    scheduled.set(false);
                }

                schedule();

                return seed;
            }

            void schedule()
            {
                if (!scheduled.getAndSet(true))
                {
                    entropyDaemon.addTask(new EntropyGatherer(entropySource));
                }
            }

            public int entropySize()
            {
                return byteLength * 8;
            }

            private class EntropyGatherer
                implements Runnable
            {
                private final IncrementalEntropySource baseRandom;

                EntropyGatherer(IncrementalEntropySource baseRandom)
                {
                    this.baseRandom = baseRandom;
                }

                public void run()
                {
                    try
                    {
                        entropy.set(baseRandom.getEntropy(pause));
                        seedAvailable.set(true);
                    }
                    catch (InterruptedException e)
                    {
                        if (LOG.isLoggable(Level.FINE))
                        {
                            LOG.fine("entropy request interrupted - exiting");
                        }
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }

    private static class IncrementalEntropySourceProvider
        implements EntropySourceProvider
    {
        private final SecureRandom random;
        private final boolean predictionResistant;

        /**
         * Create a entropy source provider based on the passed in SecureRandom.
         *
         * @param random                the SecureRandom to base EntropySource construction on.
         * @param isPredictionResistant boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is).
         */
        public IncrementalEntropySourceProvider(SecureRandom random, boolean isPredictionResistant)
        {
            this.random = random;
            this.predictionResistant = isPredictionResistant;
        }

        /**
         * Return an entropy source that will create bitsRequired bits of entropy on
         * each invocation of getEntropy().
         *
         * @param bitsRequired size (in bits) of entropy to be created by the provided source.
         * @return an EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method.
         */
        public EntropySource get(final int bitsRequired)
        {
            return new IncrementalEntropySource()
            {
                final int numBytes = (bitsRequired + 7) / 8;

                public boolean isPredictionResistant()
                {
                    return predictionResistant;
                }

                public byte[] getEntropy()
                {
                    try
                    {
                        return getEntropy(0);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                    }
                }

                public byte[] getEntropy(long pause)
                    throws InterruptedException
                {
                    byte[] seed = new byte[numBytes];
                    for (int i = 0; i < numBytes / 8; i++)
                    {
                        // we need to be mindful that we may not be the only thread/process looking for entropy
                        sleep(pause);
                        byte[] rn = random.generateSeed(8);
                        System.arraycopy(rn, 0, seed, i * 8, rn.length);
                    }

                    int extra = numBytes - ((numBytes / 8) * 8);
                    if (extra != 0)
                    {
                        sleep(pause);
                        byte[] rn = random.generateSeed(extra);
                        System.arraycopy(rn, 0, seed, seed.length - rn.length, rn.length);
                    }

                    return seed;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }
}
