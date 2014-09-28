package com.thunderbird.thickfog;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

// -- ECB encryption class, use for short data (file name, manifest file)
public class Crypto_AES_CBC extends Crypto {
  public Crypto_AES_CBC(byte[] pass, byte[] iv) {
    super(pass, iv);
  }

  @Override
  public void initCiphers() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    // -- Init Encryptor
    encryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
    SecretKey keyValue = new SecretKeySpec(key, "AES");
    AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keyValue, IVspec);

    // -- Init Decryptor
    decryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
    decryptCipher.init(Cipher.DECRYPT_MODE, keyValue, IVspec);
  }

  @Override
  public void encrypt(InputStream is, OutputStream os) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] buffer = new byte[BLOCK_SIZE];
    int noBytes = 0;
    byte[] cipherBlock = new byte[encryptCipher.getOutputSize(buffer.length)];
    int cipherBytes;

    while((noBytes = is.read(buffer))!=-1)
    {
      cipherBytes = encryptCipher.update(buffer, 0, noBytes, cipherBlock);
      os.write(cipherBlock, 0, cipherBytes);
    }

    cipherBytes = encryptCipher.doFinal(cipherBlock, 0);
    os.write(cipherBlock, 0, cipherBytes);
  }

  @Override
  public void decrypt(InputStream is, OutputStream os) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] buffer = new byte[BLOCK_SIZE];
    int noBytes = 0;
    byte[] cipherBlock = new byte[decryptCipher.getOutputSize(buffer.length)];
    int cipherBytes;

    while((noBytes = is.read(buffer))!=-1)
    {
      cipherBytes = decryptCipher.update(buffer, 0, noBytes, cipherBlock);
      os.write(cipherBlock, 0, cipherBytes);
    }

    cipherBytes = decryptCipher.doFinal(cipherBlock, 0);
    os.write(cipherBlock, 0, cipherBytes);
  }

  // -- Encrypt string and return Hex representation to avoid charset troubles
  public String encrypt(String s) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    ByteArrayInputStream ba_in = new ByteArrayInputStream(s.getBytes("UTF-8"));
    ByteArrayOutputStream ba_out = new ByteArrayOutputStream();
    encrypt(ba_in, ba_out);
    return Utils.base62encode(ba_out.toByteArray());
  }

  // -- Encrypt Hex representation string
  public String decrypt(String s) throws IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, Base64DecodingException {
    ByteArrayInputStream ba_in = new ByteArrayInputStream(Utils.base62decode(s));
    ByteArrayOutputStream ba_out = new ByteArrayOutputStream();
    decrypt(ba_in, ba_out);
    return ba_out.toString("UTF-8");
  }
}