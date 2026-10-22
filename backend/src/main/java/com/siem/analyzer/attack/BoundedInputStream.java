package com.siem.analyzer.attack;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

final class BoundedInputStream extends FilterInputStream {

    static final class TooLarge extends IOException {

        private static final long serialVersionUID = 1L;

        private final long limit;

        TooLarge(long limit) {
            super("more than " + limit + " bytes");
            this.limit = limit;
        }

        long limit() {
            return limit;
        }
    }

    private final long limit;
    private long count;

    BoundedInputStream(InputStream in, long limit) {
        super(in);
        this.limit = limit;
    }

    @Override
    public int read() throws IOException {
        int read = super.read();
        if (read >= 0) {
            counted(1);
        }
        return read;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        int read = super.read(buffer, offset, length);
        if (read > 0) {
            counted(read);
        }
        return read;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = super.skip(n);
        counted(skipped);
        return skipped;
    }

    private void counted(long bytes) throws TooLarge {
        count += bytes;
        if (count > limit) {
            throw new TooLarge(limit);
        }
    }
}
