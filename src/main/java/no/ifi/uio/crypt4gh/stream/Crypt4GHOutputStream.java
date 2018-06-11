package no.ifi.uio.crypt4gh.stream;

import no.ifi.uio.crypt4gh.factory.HeaderFactory;
import no.ifi.uio.crypt4gh.pojo.EncryptionAlgorithm;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.HashingAlgorithm;
import org.c02e.jpgpj.Key;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Crypt4GHOutputStream extends FilterOutputStream {

    public static final String PROTOCOL_NAME = "crypt4gh";
    public static final int VERSION = 1;
    public static final int KEY_LENGTH = 256;
    public static final int IV_LENGTH = 16;
    public static final int NUMBER_OF_RECORDS = 1;
    public static final int PLAINTEXT_START = 0;
    public static final int PLAINTEXT_END = -1;
    public static final int CIPHERTEXT_START = 32; // SHA256 checksum
    public static final int CIPHERTEXT_END = -1;

    public Crypt4GHOutputStream(OutputStream out, String key) throws IOException, NoSuchAlgorithmException, PGPException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        super(out);

        SecureRandom secureRandom = new SecureRandom();
        String alias = EncryptionAlgorithm.AES_256_CTR.getAlias();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(alias.split("/")[0]);
        keyGenerator.init(KEY_LENGTH, secureRandom);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] ivBytes = new byte[IV_LENGTH];
        secureRandom.nextBytes(ivBytes);

        ByteArrayOutputStream decryptedHeaderOutputStream = new ByteArrayOutputStream();
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(NUMBER_OF_RECORDS).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(PLAINTEXT_START).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(PLAINTEXT_END).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(CIPHERTEXT_START).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(CIPHERTEXT_END).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(EncryptionAlgorithm.AES_256_CTR.getCode()).array());
        decryptedHeaderOutputStream.write(sessionKey.getEncoded());
        decryptedHeaderOutputStream.write(ivBytes);
        ByteArrayInputStream decryptedHeaderInputStream = new ByteArrayInputStream(decryptedHeaderOutputStream.toByteArray());

        ByteArrayOutputStream encryptedHeaderOutputStream = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor(new Key(key));
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(decryptedHeaderInputStream, encryptedHeaderOutputStream);
        encryptedHeaderOutputStream.close();
        byte[] encryptedHeader = encryptedHeaderOutputStream.toByteArray();

        out.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).put(PROTOCOL_NAME.getBytes()).array());
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(VERSION).array());
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(HeaderFactory.UNENCRYPTED_HEADER_LENGTH + encryptedHeader.length).array());
        out.write(encryptedHeader);
        out.write(ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).array()); // Fake SHA256 checksum

        Cipher cipher = Cipher.getInstance(alias);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(ivBytes));
        this.out = new CipherOutputStream(out, cipher);
    }

}