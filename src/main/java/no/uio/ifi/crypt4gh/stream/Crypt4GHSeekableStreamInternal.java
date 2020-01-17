package no.uio.ifi.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import lombok.extern.slf4j.Slf4j;
import no.uio.ifi.crypt4gh.pojo.body.Segment;
import no.uio.ifi.crypt4gh.pojo.header.DataEditList;
import no.uio.ifi.crypt4gh.pojo.header.DataEncryptionParameters;
import no.uio.ifi.crypt4gh.pojo.header.Header;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Internal part of Crypt4GHInputStream that wraps existing InputStream, not a public API.
 */
@Slf4j
public class Crypt4GHSeekableStreamInternal extends SeekableStream {

    private Header header;
    private int[] buffer;
    private byte[] bbuffer;
    private int bytesRead;
    private Collection<DataEncryptionParameters> dataEncryptionParametersList;
    private Optional<DataEditList> dataEditList;
    private int encryptedSegmentSize;
    private int lastDecryptedSegment = -1;

    // SeekableStream:
    // For each read: read/decrypt segment, return byte range
    // Each position matches a segment.
    private SeekableStream wrappedEncryptedStream;
    private long position = 0;          // Position in the unencrypted stream
    private int wrappedDelta = 0;       // Length of the header
    private long contentLength = -1;    // Length of the unencrypted stream
    private long curBuf = -1;           // index of current buffer in menory
    private int plainSegSize = 65536;  // Size of unencrypted segment
    
    private boolean eof_ = false;
    
    /**
     * Constructs the internal part of Crypt4GHInputStream that wraps existing InputStream, not a public API.
     */
    public Crypt4GHSeekableStreamInternal(SeekableStream encryptedStream, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        this.header = new Header(encryptedStream, readerPrivateKey);
        this.dataEncryptionParametersList = header.getDataEncryptionParametersList();
        DataEncryptionParameters firstDataEncryptionParameters = dataEncryptionParametersList.iterator().next();
        for (DataEncryptionParameters encryptionParameters : dataEncryptionParametersList) {
            if (firstDataEncryptionParameters.getDataEncryptionMethod() != encryptionParameters.getDataEncryptionMethod()) {
                throw new GeneralSecurityException("Different Data Encryption Methods are not supported");
            }
        }
        this.encryptedSegmentSize = firstDataEncryptionParameters.getDataEncryptionMethod().getEncryptedSegmentSize();
        this.dataEditList = header.getDataEditList();
        
        wrappedEncryptedStream = encryptedStream;
        position = 0; // header-offset included
        wrappedDelta = (int) wrappedEncryptedStream.position(); // Post-header
        
        // Estimate content length;
        long enc = this.wrappedEncryptedStream.length() - wrappedDelta;
        long numSegments = enc / this.encryptedSegmentSize;
        this.contentLength = (plainSegSize*numSegments) + ((enc-(this.encryptedSegmentSize*numSegments)) - (this.encryptedSegmentSize-plainSegSize) );
    }

    Optional<DataEditList> getDataEditList() {
        return dataEditList;
    }

    /**
     * Gets header.
     *
     * @return Crypt4GH full header.
     */
    Header getHeader() {
        return header;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        if (this.eof_) {
            return -1;
        }
        
        long segNum = this.position / this.plainSegSize;
        int bufIndex = getSegment(segNum);
        
        this.position++;
        return buffer[bufIndex];
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        /*
            Reusing default `InputStream`'s implementation, because `FilterStream`'s implementation doesn't fit
         */
        Objects.checkFromIndexSize(off, len, b.length);
        if (len == 0) {
            return 0;
        }
        
        if (this.eof_ || this.position > this.contentLength) {
            return -1;
        }
        
        int c = read();
        if (c == -1) {
            return -1;
        }
        this.position--;
        
        // Read segment-by-segment
        int remaining = len;
        int curOff = off;
        int read = 0;
        
        while (remaining > 0) {
            long segNum = this.position / this.plainSegSize; // Current Segment
            int bufIndex = getSegment(segNum); // Ensure segment is in memory buffer
            //int bufRemaining = this.plainSegSize - bufIndex; // how much data betwen now and buffer end?
            int bufRemaining = bbuffer.length - bufIndex; // how much data betwen now and buffer end?
            
            int toCopy = bufRemaining>remaining?remaining:bufRemaining;
//            byte[] bbuffer = integersToBytes(this.buffer);
//            System.arraycopy(this.buffer, bufIndex, b, curOff, toCopy);
            System.arraycopy(bbuffer, bufIndex, b, curOff, toCopy);
            
            // Adjust indexes for multiple-segment reads
            read += toCopy;
            remaining -= toCopy;
            curOff += toCopy;
            this.position += toCopy;
            
            if (bbuffer.length < this.plainSegSize && bufRemaining < remaining) {
                this.eof_ = true;
                remaining = 0;
                //this.position = this.contentLength+1;
            }
        }
        
        return read;
    }
    
    private byte[] integersToBytes(int[] values) throws IOException
    {
        byte[] result = new byte[values.length];
        for (int i=0; i< result.length; i++)
            result[i] = (byte)values[i];

       return result;
    }          
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void readFully(byte[] b) throws IOException {
        int read = 0;
        
        while(read<b.length) {
            read += read(b, read, (b.length-read));
        }
        
        return;
    }
    
    private synchronized int getSegment(long segNum) throws IOException {
        if (this.curBuf == segNum) {
            return (int) (this.position - (segNum * this.plainSegSize));
        }
        
        long tempPos = this.position;
        this.position = (segNum * this.encryptedSegmentSize);
        this.wrappedEncryptedStream.seek(this.position + this.wrappedDelta);

        fillBuffer();
        this.curBuf = segNum;
        
        this.position = tempPos;
        this.wrappedEncryptedStream.seek(this.position + this.wrappedDelta);
        
        return (int) (this.position - (segNum * this.plainSegSize));
    }
    
    private synchronized void fillBuffer() throws IOException {
        byte[] encryptedSegmentBytes = wrappedEncryptedStream.readNBytes(encryptedSegmentSize);
        if (encryptedSegmentBytes.length == 0) {
            this.eof_ = true;
            Arrays.fill(buffer, (byte) (-1));
        } else {
            try {
                decryptSegment(encryptedSegmentBytes);
            } catch (GeneralSecurityException ex) {
                Logger.getLogger(Crypt4GHSeekableStreamInternal.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        bytesRead = 0;
    }

    private synchronized void decryptSegment(byte[] encryptedSegmentBytes) throws GeneralSecurityException, IOException {
        Segment segment = Segment.create(encryptedSegmentBytes, dataEncryptionParametersList);
        //byte[] unencryptedData = segment.getUnencryptedData();
        bbuffer = segment.getUnencryptedData();
        buffer = new int[bbuffer.length];
        for (int i = 0; i < bbuffer.length; i++) {
            buffer[i] = (bbuffer[i] & 0xff);
        }
        lastDecryptedSegment++;
    }

    /*
     * SeekableStream Additions
     */    
    
    @Override
    public long length() {
        return contentLength;
    }

    @Override
    public long position() throws IOException {
        return this.position;
    }

    @Override
    public void seek(long position) throws IOException {
        this.position = position;
    }

    @Override
    public void close() throws IOException {
        this.wrappedEncryptedStream.close();
    }

    @Override
    public boolean eof() throws IOException {
        if (this.wrappedEncryptedStream.eof()) {
            return true;
        } else if(this.contentLength > 0 && this.position > this.contentLength) {
            return true;
        }
        return  false;
    }

    @Override
    public String getSource() {
        String source = this.wrappedEncryptedStream.getSource();
        if (source.toLowerCase().endsWith("c4gh")) {
            source = source.substring(0, (source.length()-5) );
        } else if (source.toLowerCase().endsWith("enc")) {
            source = source.substring(0, (source.length()-4) );
        }

        return source;
    }

}
