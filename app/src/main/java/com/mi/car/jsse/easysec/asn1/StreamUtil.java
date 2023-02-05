package com.mi.car.jsse.easysec.asn1;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;

class StreamUtil {
    private static final long MAX_MEMORY = Runtime.getRuntime().maxMemory();

    StreamUtil() {
    }

    static int findLimit(InputStream in) {
        long size;
        if (in instanceof LimitedInputStream) {
            return ((LimitedInputStream) in).getLimit();
        }
        if (in instanceof ASN1InputStream) {
            return ((ASN1InputStream) in).getLimit();
        }
        if (in instanceof ByteArrayInputStream) {
            return ((ByteArrayInputStream) in).available();
        }
        if (in instanceof FileInputStream) {
            try {
                FileChannel channel = ((FileInputStream) in).getChannel();
                if (channel != null) {
                    size = channel.size();
                } else {
                    size = 2147483647L;
                }
                if (size < 2147483647L) {
                    return (int) size;
                }
            } catch (IOException e) {
            }
        }
        if (MAX_MEMORY > 2147483647L) {
            return Integer.MAX_VALUE;
        }
        return (int) MAX_MEMORY;
    }
}
