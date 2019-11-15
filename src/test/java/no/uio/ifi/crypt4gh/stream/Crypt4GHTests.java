package no.uio.ifi.crypt4gh.stream;

import no.uio.ifi.crypt4gh.pojo.header.DataEditList;
import no.uio.ifi.crypt4gh.pojo.header.Header;
import no.uio.ifi.crypt4gh.util.Crypt4GHUtils;
import no.uio.ifi.crypt4gh.util.KeyUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;

import static no.uio.ifi.crypt4gh.pojo.body.Segment.UNENCRYPTED_DATA_SEGMENT_SIZE;

/**
 * A bunch of tests for Crypt4GH Input/Output streams with or without skip-access and DataEditLists.
 */
@RunWith(JUnit4.class)
public class Crypt4GHTests {

    private KeyUtils keyUtils = KeyUtils.getInstance();
    private Crypt4GHUtils crypt4GHUtils = Crypt4GHUtils.getInstance();

    /**
     * Tests reencryption of a byte-array generated in memory with OpenSSL keys.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void memoryReencryptionOpenSSLKeys() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);

        byte[] unencryptedData = new byte[1024 * 1024];
        SecureRandom.getInstanceStrong().nextBytes(unencryptedData);

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(byteArrayOutputStream, writerPrivateKey, readerPublicKey)) {
                crypt4GHOutputStream.write(unencryptedData);
            }
            byte[] encryptedData = byteArrayOutputStream.toByteArray();
            try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptedData);
                 Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(byteArrayInputStream, readerPrivateKey)) {
                byte[] decryptedData = crypt4GHInputStream.readAllBytes();
                Assert.assertArrayEquals(unencryptedData, decryptedData);
            }
        }
    }

    /**
     * Tests reencryption of a byte-array generated in memory with keys generated by the library itself.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void memoryReencryptionOwnKeys() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.generatePrivateKey();
        KeyPair readerKeyPair = keyUtils.generateKeyPair();
        PrivateKey readerPrivateKey = readerKeyPair.getPrivate();
        PublicKey readerPublicKey = readerKeyPair.getPublic();

        byte[] unencryptedData = new byte[1024 * 1024];
        SecureRandom.getInstanceStrong().nextBytes(unencryptedData);

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(byteArrayOutputStream, writerPrivateKey, readerPublicKey)) {
                crypt4GHOutputStream.write(unencryptedData);
            }
            byte[] encryptedData = byteArrayOutputStream.toByteArray();
            try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptedData);
                 Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(byteArrayInputStream, readerPrivateKey)) {
                byte[] decryptedData = crypt4GHInputStream.readAllBytes();
                Assert.assertArrayEquals(unencryptedData, decryptedData);
            }
        }
    }

    /**
     * Tests reencryption of a file on a file-system.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void fileReencryptionTest() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);

        File unencryptedFile = new File(getClass().getClassLoader().getResource("sample.txt").getFile());
        File encryptedFile = Files.createTempFile("test", "enc").toFile();
        File decryptedFile = Files.createTempFile("test", "dec").toFile();
        try (FileInputStream inputStream = new FileInputStream(unencryptedFile);
             FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, writerPrivateKey, readerPublicKey)) {
                IOUtils.copy(inputStream, crypt4GHOutputStream);
            }
        }
        try (FileInputStream inputStream = new FileInputStream(encryptedFile);
             FileOutputStream outputStream = new FileOutputStream(decryptedFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(inputStream, readerPrivateKey)) {
            IOUtils.copy(crypt4GHInputStream, outputStream);
            Assert.assertEquals(FileUtils.readFileToString(unencryptedFile, Charset.defaultCharset()), FileUtils.readFileToString(decryptedFile, Charset.defaultCharset()));
        } finally {
            encryptedFile.delete();
            decryptedFile.delete();
        }
    }

    /**
     * Tests reencryption of a file on a file-system with skipping forward to some specified byte.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void partialFileReencryptionTest() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);

        File unencryptedFile = new File(getClass().getClassLoader().getResource("sample.txt").getFile());
        File encryptedFile = Files.createTempFile("test", "enc").toFile();
        File decryptedFile = Files.createTempFile("test", "dec").toFile();
        try (FileInputStream inputStream = new FileInputStream(unencryptedFile);
             FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, writerPrivateKey, readerPublicKey)) {
                IOUtils.copy(inputStream, crypt4GHOutputStream);
            }
        }
        try (FileInputStream encryptedInputStream = new FileInputStream(encryptedFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(encryptedInputStream, readerPrivateKey);
             FileInputStream unencryptedInputStream = new FileInputStream(unencryptedFile)) {
            unencryptedInputStream.skip(UNENCRYPTED_DATA_SEGMENT_SIZE + 100);
            crypt4GHInputStream.skip(UNENCRYPTED_DATA_SEGMENT_SIZE + 100);
            Assert.assertArrayEquals(unencryptedInputStream.readAllBytes(), crypt4GHInputStream.readAllBytes());
        } finally {
            encryptedFile.delete();
            decryptedFile.delete();
        }
    }

    /**
     * Tests reencryption of a file on a file-system with DataEditList.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void fileReencryptionWithDataEditListTest() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);

        File unencryptedFile = new File(getClass().getClassLoader().getResource("sample.txt").getFile());
        File encryptedFile = Files.createTempFile("test", "enc").toFile();
        File decryptedFile = Files.createTempFile("test", "dec").toFile();
        try (FileInputStream inputStream = new FileInputStream(unencryptedFile);
             FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, writerPrivateKey, readerPublicKey)) {
                IOUtils.copy(inputStream, crypt4GHOutputStream);
            }
        }
        DataEditList dataEditList = new DataEditList(new long[]{950, 837, 510, 847});
        try (FileInputStream encryptedInputStream = new FileInputStream(encryptedFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(encryptedInputStream, dataEditList, readerPrivateKey);
             FileInputStream unencryptedInputStream = new FileInputStream(unencryptedFile)) {
            List<String> lines = IOUtils.readLines(crypt4GHInputStream, Charset.defaultCharset());
            Assert.assertNotNull(lines);
            Assert.assertEquals(2, lines.size());
            unencryptedInputStream.skip(950);
            String firstLine = new String(unencryptedInputStream.readNBytes(837)).trim();
            Assert.assertEquals(firstLine, lines.get(0));
            unencryptedInputStream.skip(510);
            String secondLine = new String(unencryptedInputStream.readNBytes(847)).trim();
            Assert.assertEquals(secondLine, lines.get(1));
        } finally {
            encryptedFile.delete();
            decryptedFile.delete();
        }
    }

    /**
     * Tests reencryption of a file on a file-system with DataEditList injected to OutputStream and skipping forward to some specified byte.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void partialFileReencryptionWithDataEditListInOutputStreamTest() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);

        File unencryptedFile = new File(getClass().getClassLoader().getResource("sample.txt").getFile());
        File encryptedFile = Files.createTempFile("test", "enc").toFile();
        File decryptedFile = Files.createTempFile("test", "dec").toFile();
        DataEditList dataEditList = new DataEditList(new long[]{950, 837, 510, 847});
        try (FileInputStream inputStream = new FileInputStream(unencryptedFile);
             FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, dataEditList, writerPrivateKey, readerPublicKey)) {
                IOUtils.copy(inputStream, crypt4GHOutputStream);
            }
        }

        try (FileInputStream encryptedInputStream = new FileInputStream(encryptedFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(encryptedInputStream, readerPrivateKey);
             FileInputStream unencryptedInputStream = new FileInputStream(unencryptedFile)) {
            crypt4GHInputStream.skip(840);
            List<String> lines = IOUtils.readLines(crypt4GHInputStream, Charset.defaultCharset());
            Assert.assertNotNull(lines);
            Assert.assertEquals(1, lines.size());
            unencryptedInputStream.skip(950 + 837 + 510 + 3);
            String line = new String(unencryptedInputStream.readNBytes(843)).trim();
            Assert.assertEquals(line, lines.get(0));
        } finally {
            encryptedFile.delete();
            decryptedFile.delete();
        }
    }

    /**
     * Tests reencryption of a file on a file-system with DataEditList applied to InputStream and skipping forward to some specified byte.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void partialFileReencryptionWithDataEditListInInputStreamTest() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);

        File unencryptedFile = new File(getClass().getClassLoader().getResource("sample.txt").getFile());
        File encryptedFile = Files.createTempFile("test", "enc").toFile();
        File decryptedFile = Files.createTempFile("test", "dec").toFile();
        try (FileInputStream inputStream = new FileInputStream(unencryptedFile);
             FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, writerPrivateKey, readerPublicKey)) {
                IOUtils.copy(inputStream, crypt4GHOutputStream);
            }
        }
        DataEditList dataEditList = new DataEditList(new long[]{950, 837, 510, 847});
        try (FileInputStream encryptedInputStream = new FileInputStream(encryptedFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(encryptedInputStream, dataEditList, readerPrivateKey);
             FileInputStream unencryptedInputStream = new FileInputStream(unencryptedFile)) {
            crypt4GHInputStream.skip(840);
            List<String> lines = IOUtils.readLines(crypt4GHInputStream, Charset.defaultCharset());
            Assert.assertNotNull(lines);
            Assert.assertEquals(1, lines.size());
            unencryptedInputStream.skip(950 + 837 + 510 + 3);
            String line = new String(unencryptedInputStream.readNBytes(843)).trim();
            Assert.assertEquals(line, lines.get(0));
        } finally {
            encryptedFile.delete();
            decryptedFile.delete();
        }
    }

    /**
     * Tests adding recipient to a header.
     *
     * @throws Exception In case something fails.
     */
    @Test
    public void addRecipientToHeaderTest() throws Exception {
        PrivateKey writerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("writer.sec.pem").getFile()), PrivateKey.class);
        PrivateKey readerPrivateKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.sec.pem").getFile()), PrivateKey.class);
        PublicKey readerPublicKey = keyUtils.readPEMFile(new File(getClass().getClassLoader().getResource("reader.pub.pem").getFile()), PublicKey.class);
        KeyPair anotherReaderKeyPair = keyUtils.generateKeyPair();

        File unencryptedFile = new File(getClass().getClassLoader().getResource("sample.txt").getFile());
        File encryptedFile = Files.createTempFile("test", "enc").toFile();
        File encryptedFileWithAddedRecipient = Files.createTempFile("test2", "enc").toFile();
        File decryptedFile = Files.createTempFile("test", "dec").toFile();
        DataEditList dataEditList = new DataEditList(new long[]{950, 837, 510, 847});
        Header header;
        try (FileInputStream inputStream = new FileInputStream(unencryptedFile);
             FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            try (Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, dataEditList, writerPrivateKey, readerPublicKey)) {
                IOUtils.copy(inputStream, crypt4GHOutputStream);
                header = crypt4GHOutputStream.getHeader();
            }
        }

        int headerLength = header.serialize().length;
        header = crypt4GHUtils.addRecipient(header.serialize(), readerPrivateKey, anotherReaderKeyPair.getPublic());
        Assert.assertEquals(4, header.getHeaderPackets().size());

        try (FileInputStream encryptedInputStream = new FileInputStream(encryptedFile);
             FileOutputStream encryptedOutputStream = new FileOutputStream(encryptedFileWithAddedRecipient)) {
            encryptedOutputStream.write(header.serialize());
            encryptedInputStream.skip(headerLength);
            IOUtils.copyLarge(encryptedInputStream, encryptedOutputStream);
        }

        try (FileInputStream encryptedInputStream = new FileInputStream(encryptedFileWithAddedRecipient);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(encryptedInputStream, anotherReaderKeyPair.getPrivate());
             FileInputStream unencryptedInputStream = new FileInputStream(unencryptedFile)) {
            crypt4GHInputStream.skip(840);
            List<String> lines = IOUtils.readLines(crypt4GHInputStream, Charset.defaultCharset());
            Assert.assertNotNull(lines);
            Assert.assertEquals(1, lines.size());
            unencryptedInputStream.skip(950 + 837 + 510 + 3);
            String line = new String(unencryptedInputStream.readNBytes(843)).trim();
            Assert.assertEquals(line, lines.get(0));
        } finally {
            encryptedFile.delete();
            encryptedFileWithAddedRecipient.delete();
            decryptedFile.delete();
        }
    }

}
