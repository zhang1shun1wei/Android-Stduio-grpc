package com.mi.car.jsse.easysec.util;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.util.encoders.UTF8;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Vector;

public final class Strings {
    private static String LINE_SEPARATOR;

    public Strings() {
    }

    public static String fromUTF8ByteArray(byte[] bytes) {
        char[] chars = new char[bytes.length];
        int len = UTF8.transcodeToUTF16(bytes, chars);
        if (len < 0) {
            throw new IllegalArgumentException("Invalid UTF-8 input");
        } else {
            return new String(chars, 0, len);
        }
    }

    public static String fromUTF8ByteArray(byte[] bytes, int off, int length) {
        char[] chars = new char[length];
        int len = UTF8.transcodeToUTF16(bytes, off, length, chars);
        if (len < 0) {
            throw new IllegalArgumentException("Invalid UTF-8 input");
        } else {
            return new String(chars, 0, len);
        }
    }

    public static byte[] toUTF8ByteArray(String string) {
        return toUTF8ByteArray(string.toCharArray());
    }

    public static byte[] toUTF8ByteArray(char[] string) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            toUTF8ByteArray(string, bOut);
        } catch (IOException var3) {
            throw new IllegalStateException("cannot encode string to byte array!");
        }

        return bOut.toByteArray();
    }

    public static void toUTF8ByteArray(char[] string, OutputStream sOut) throws IOException {
        char[] c = string;

        for(int i = 0; i < c.length; ++i) {
            char ch = c[i];
            if (ch < 128) {
                sOut.write(ch);
            } else if (ch < 2048) {
                sOut.write(192 | ch >> 6);
                sOut.write(128 | ch & 63);
            } else if (ch >= '\ud800' && ch <= '\udfff') {
                if (i + 1 >= c.length) {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }

                char W1 = ch;
                ++i;
                ch = c[i];
                if (W1 > '\udbff') {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }

                int codePoint = ((W1 & 1023) << 10 | ch & 1023) + 65536;
                sOut.write(240 | codePoint >> 18);
                sOut.write(128 | codePoint >> 12 & 63);
                sOut.write(128 | codePoint >> 6 & 63);
                sOut.write(128 | codePoint & 63);
            } else {
                sOut.write(224 | ch >> 12);
                sOut.write(128 | ch >> 6 & 63);
                sOut.write(128 | ch & 63);
            }
        }

    }

    public static String toUpperCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for(int i = 0; i != chars.length; ++i) {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch) {
                changed = true;
                chars[i] = (char)(ch - 97 + 65);
            }
        }

        if (changed) {
            return new String(chars);
        } else {
            return string;
        }
    }

    public static String toLowerCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for(int i = 0; i != chars.length; ++i) {
            char ch = chars[i];
            if ('A' <= ch && 'Z' >= ch) {
                changed = true;
                chars[i] = (char)(ch - 65 + 97);
            }
        }

        if (changed) {
            return new String(chars);
        } else {
            return string;
        }
    }

    public static byte[] toByteArray(char[] chars) {
        byte[] bytes = new byte[chars.length];

        for(int i = 0; i != bytes.length; ++i) {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

    public static byte[] toByteArray(String string) {
        byte[] bytes = new byte[string.length()];

        for(int i = 0; i != bytes.length; ++i) {
            char ch = string.charAt(i);
            bytes[i] = (byte)ch;
        }

        return bytes;
    }

    public static int toByteArray(String s, byte[] buf, int off) {
        int count = s.length();

        for(int i = 0; i < count; ++i) {
            char c = s.charAt(i);
            buf[off + i] = (byte)c;
        }

        return count;
    }

    public static boolean constantTimeAreEqual(String a, String b) {
        boolean isEqual = a.length() == b.length();
        int len = a.length();

        for(int i = 0; i != len; ++i) {
            isEqual &= a.charAt(i) == b.charAt(i);
        }

        return isEqual;
    }

    public static String fromByteArray(byte[] bytes) {
        return new String(asCharArray(bytes));
    }

    public static char[] asCharArray(byte[] bytes) {
        char[] chars = new char[bytes.length];

        for(int i = 0; i != chars.length; ++i) {
            chars[i] = (char)(bytes[i] & 255);
        }

        return chars;
    }

    public static String[] split(String input, char delimiter) {
        Vector v = new Vector();
        boolean moreTokens = true;

        while(moreTokens) {
            int tokenLocation = input.indexOf(delimiter);
            if (tokenLocation > 0) {
                String subString = input.substring(0, tokenLocation);
                v.addElement(subString);
                input = input.substring(tokenLocation + 1);
            } else {
                moreTokens = false;
                v.addElement(input);
            }
        }

        String[] res = new String[v.size()];

        for(int i = 0; i != res.length; ++i) {
            res[i] = (String)v.elementAt(i);
        }

        return res;
    }

    public static StringList newList() {
        return new Strings.StringListImpl();
    }

    public static String lineSeparator() {
        return LINE_SEPARATOR;
    }

    static {
        try {
            LINE_SEPARATOR = (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty("line.separator");
                }
            });
        } catch (Exception var3) {
            try {
                LINE_SEPARATOR = String.format("%n");
            } catch (Exception var2) {
                LINE_SEPARATOR = "\n";
            }
        }

    }

    private static class StringListImpl extends ArrayList<String> implements StringList {
        private StringListImpl() {
        }

        public boolean add(String s) {
            return super.add(s);
        }

        public String set(int index, String element) {
            return (String)super.set(index, element);
        }

        public void add(int index, String element) {
            super.add(index, element);
        }

        public String[] toStringArray() {
            String[] strs = new String[this.size()];

            for(int i = 0; i != strs.length; ++i) {
                strs[i] = (String)this.get(i);
            }

            return strs;
        }

        public String[] toStringArray(int from, int to) {
            String[] strs = new String[to - from];

            for(int i = from; i != this.size() && i != to; ++i) {
                strs[i - from] = (String)this.get(i);
            }

            return strs;
        }
    }
}
