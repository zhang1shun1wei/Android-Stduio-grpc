package com.mi.car.jsse.easysec.crypto.examples;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.engines.DESedeEngine;
import com.mi.car.jsse.easysec.crypto.generators.DESedeKeyGenerator;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.paddings.PaddedBufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;

public class DESExample {
    private boolean encrypt = true;
    private PaddedBufferedBlockCipher cipher = null;
    private BufferedInputStream in = null;
    private BufferedOutputStream out = null;
    private byte[] key = null;

    public static void main(String[] args) {
        boolean encrypt = true;
        String infile = null;
        String outfile = null;
        String keyfile = null;
        DESExample de;
        if (args.length < 2) {
            de = new DESExample();
            System.err.println("Usage: java " + de.getClass().getName() + " infile outfile [keyfile]");
            System.exit(1);
        }

        keyfile = "deskey.dat";
        infile = args[0];
        outfile = args[1];
        if (args.length > 2) {
            encrypt = false;
            keyfile = args[2];
        }

        de = new DESExample(infile, outfile, keyfile, encrypt);
        de.process();
    }

    public DESExample() {
    }

    public DESExample(String infile, String outfile, String keyfile, boolean encrypt) {
        this.encrypt = encrypt;

        try {
            this.in = new BufferedInputStream(new FileInputStream(infile));
        } catch (FileNotFoundException var14) {
            System.err.println("Input file not found [" + infile + "]");
            System.exit(1);
        }

        try {
            this.out = new BufferedOutputStream(new FileOutputStream(outfile));
        } catch (IOException var13) {
            System.err.println("Output file not created [" + outfile + "]");
            System.exit(1);
        }

        if (encrypt) {
            try {
                SecureRandom sr = null;

                try {
                    sr = new SecureRandom();
                    sr.setSeed("www.bouncycastle.org".getBytes());
                } catch (Exception var11) {
                    System.err.println("Hmmm, no SHA1PRNG, you need the Sun implementation");
                    System.exit(1);
                }

                KeyGenerationParameters kgp = new KeyGenerationParameters(sr, 192);
                DESedeKeyGenerator kg = new DESedeKeyGenerator();
                kg.init(kgp);
                this.key = kg.generateKey();
                BufferedOutputStream keystream = new BufferedOutputStream(new FileOutputStream(keyfile));
                byte[] keyhex = Hex.encode(this.key);
                keystream.write(keyhex, 0, keyhex.length);
                keystream.flush();
                keystream.close();
            } catch (IOException var12) {
                System.err.println("Could not decryption create key file [" + keyfile + "]");
                System.exit(1);
            }
        } else {
            try {
                BufferedInputStream keystream = new BufferedInputStream(new FileInputStream(keyfile));
                int len = keystream.available();
                byte[] keyhex = new byte[len];
                keystream.read(keyhex, 0, len);
                this.key = Hex.decode(keyhex);
            } catch (IOException var10) {
                System.err.println("Decryption key file not found, or not valid [" + keyfile + "]");
                System.exit(1);
            }
        }

    }

    private void process() {
        this.cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
        if (this.encrypt) {
            this.performEncrypt(this.key);
        } else {
            this.performDecrypt(this.key);
        }

        try {
            this.in.close();
            this.out.flush();
            this.out.close();
        } catch (IOException var2) {
            System.err.println("exception closing resources: " + var2.getMessage());
        }

    }

    private void performEncrypt(byte[] key) {
        this.cipher.init(true, new KeyParameter(key));
        int inBlockSize = 47;
        int outBlockSize = this.cipher.getOutputSize(inBlockSize);
        byte[] inblock = new byte[inBlockSize];
        byte[] outblock = new byte[outBlockSize];

        try {
            Object var8 = null;

            int inL;
            int outL;
            byte[] rv;
            while((inL = this.in.read(inblock, 0, inBlockSize)) > 0) {
                outL = this.cipher.processBytes(inblock, 0, inL, outblock, 0);
                if (outL > 0) {
                    rv = Hex.encode(outblock, 0, outL);
                    this.out.write(rv, 0, rv.length);
                    this.out.write(10);
                }
            }

            try {
                outL = this.cipher.doFinal(outblock, 0);
                if (outL > 0) {
                    rv = Hex.encode(outblock, 0, outL);
                    this.out.write(rv, 0, rv.length);
                    this.out.write(10);
                }
            } catch (CryptoException var10) {
            }
        } catch (IOException var11) {
            var11.printStackTrace();
        }

    }

    private void performDecrypt(byte[] key) {
        this.cipher.init(false, new KeyParameter(key));
        BufferedReader br = new BufferedReader(new InputStreamReader(this.in));

        try {
            byte[] inblock = null;
            byte[] outblock = null;
            String rv = null;

            int outL;
            while((rv = br.readLine()) != null) {
                inblock = Hex.decode(rv);
                outblock = new byte[this.cipher.getOutputSize(inblock.length)];
                outL = this.cipher.processBytes(inblock, 0, inblock.length, outblock, 0);
                if (outL > 0) {
                    this.out.write(outblock, 0, outL);
                }
            }

            try {
                outL = this.cipher.doFinal(outblock, 0);
                if (outL > 0) {
                    this.out.write(outblock, 0, outL);
                }
            } catch (CryptoException var8) {
            }
        } catch (IOException var9) {
            var9.printStackTrace();
        }

    }
}
