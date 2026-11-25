package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.parse.LogParser;
import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.stats.LogStats;
import io.github.aachar0.loganalyzer.model.Malformed;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

/**
 * Reads ONE byte range of a file and counts every log line that BELONGS to that range.
 *
 * The hard part: a cut at byte 1,000,000 usually lands in the middle of a line. The rule that makes
 * parallel reading correct is:
 *
 *   "A line belongs to the range that contains the line's FIRST byte."
 *
 * So a range (a) skips the partial line at its start (the previous range finishes that line), and
 * (b) keeps reading past its end until the line that started before the end is complete.
 * Every line is then counted exactly once, whatever the cut positions are. Tests check this.
 *
 * Memory: one 256 KB buffer per worker, no matter how large the file is.
 */
public final class ChunkProcessor {

    static final int BUFFER_SIZE = 256 * 1024;

    private ChunkProcessor() {
    }

    public static LogStats process(FileChannel channel, Range range, ResponseTimeUnit unit) throws IOException {
        LogStats stats = new LogStats();
        LogParser parser = new LogParser(unit);               // one parser per range: no sharing, no locks

        byte[] buf = new byte[BUFFER_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(buf);

        long readPos = range.start() > 0 ? range.start() - 1 : 0;   // next file offset to read
        long bufBase = readPos;                                       // file offset of buf[0]
        int len = 0;                                                  // number of valid bytes in buf
        int scan = 0;                                                 // where to continue looking for '\n'
        int lineStart = 0;                                            // index in buf where the current line begins
        boolean aligning = range.start() > 0;                         // still inside the partial first line?
        boolean discarding = false;                                   // inside an over-long line we are skipping?

        while (true) {
            bb.limit(buf.length);
            bb.position(len);
            int n = channel.read(bb, readPos);
            boolean eof = n < 0;
            if (!eof) {
                readPos += n;
                len += n;
            }

            for (int i = scan; i < len; i++) {
                if (buf[i] != '\n') {
                    continue;
                }
                if (aligning || discarding) {                         // end of a line we do not own / want
                    aligning = false;
                    discarding = false;
                } else {
                    if (bufBase + lineStart >= range.end()) {         // this line starts in the NEXT range
                        return stats;
                    }
                    int lineLength = i - lineStart;
                    if (lineLength > 0 && buf[i - 1] == '\r') {       // Windows line ending
                        lineLength--;
                    }
                    stats.accept(parser.parse(buf, lineStart, lineLength));
                }
                lineStart = i + 1;
            }
            scan = len;

            if (eof) {
                // The last line of a file may have no trailing newline.
                if (!aligning && !discarding && lineStart < len && bufBase + lineStart < range.end()) {
                    int lineLength = len - lineStart;
                    if (buf[len - 1] == '\r') {
                        lineLength--;
                    }
                    stats.accept(parser.parse(buf, lineStart, lineLength));
                }
                return stats;
            }

            // Make room for the next read.
            if (aligning || discarding) {                             // nothing in the buffer is needed any more
                bufBase += len;
                len = 0;
                scan = 0;
                lineStart = 0;
            } else if (lineStart > 0) {                               // move the unfinished line to the front
                System.arraycopy(buf, lineStart, buf, 0, len - lineStart);
                bufBase += lineStart;
                len -= lineStart;
                scan = len;
                lineStart = 0;
            } else if (len == buf.length) {                           // a "line" longer than the buffer: skip it
                if (bufBase >= range.end()) {
                    return stats;
                }
                stats.accept(Malformed.INSTANCE);
                discarding = true;
                bufBase += len;
                len = 0;
                scan = 0;
            }
        }
    }
}
