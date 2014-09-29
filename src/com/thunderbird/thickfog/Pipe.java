package com.thunderbird.thickfog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import java.io.*;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;

public class Pipe {
  final private static Logger LOGGER = LoggerFactory.getLogger(Pipe.class);
  final public static int CHUNK_SIZE = 4194304 - 32;     // 4MB chunk size (encrypted will be 4MB exactly)
  final static String MANIFEST_EXT = ".manifest";
  final static String CHUNK_EXT = ".part";

  private Crypto_AES_CBC lightCipher;
  private Crypto_Serpent_AES_CBC heavyChipher;
  private File originalFile;                         // Original file path & name
  private File encryptedPath;                        // Folder where file Manifest and Chunks are stored
  private FileManifest manifest;

/*  - private FileManifest
  - private HashingDigest
  - update()
  - push()
  - pull()
  - private readManifest
*/

  public Pipe(String originalFile, String encryptedPath, byte[] key0, byte[] key1, byte[] IV) {
    this.originalFile = new File(originalFile);
    this.encryptedPath = new File(encryptedPath);

    // -- create manifest and do basic initialisation
    manifest = new FileManifest();
    manifest.setName(this.originalFile.getName());
    manifest.setSize(this.originalFile.length());
    manifest.setChunks(new ArrayList<ChunkManifest>());

    try {
      lightCipher = new Crypto_AES_CBC(key0, IV);
      lightCipher.initCiphers();
      heavyChipher = new Crypto_Serpent_AES_CBC(key0, null, key1, null);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
  }

  // -- Split original file into chunks, encrypt them and create manifest file
  public void push() {
    BufferedInputStream bis = null;
    int bytesRead;

    try {
      // -- Open original file
      bis = new BufferedInputStream(new FileInputStream(originalFile));
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Opening: " + originalFile);
        LOGGER.debug("Size: " + originalFile.length() / (1024 * 1024) + "MB");
      }

      // -- Split file into chunks, calculate hashes & update manifest accordingly
      if (originalFile.length() > 0) {
        // TODO check > 4GB file
        // only bother if file is non empty
        setIVs(Utils.getSecureRandom(Crypto.BLOCK_SIZE),  // get new IV
            Utils.getSecureRandom(Crypto.BLOCK_SIZE));
        byte[] originalBuf = new byte[CHUNK_SIZE];        // original data chunk buffer
        byte[] encryptedBuf = new byte[CHUNK_SIZE];       // encrypted data chunk buffer
        int i = 0;
        MessageDigest originalFileDigest = MessageDigest.getInstance("SHA-512", "BC");
        originalFileDigest.reset();
        MessageDigest chunkDigest = MessageDigest.getInstance("SHA-512", "BC");
        while (bis.available() > 0) {
          // read chunk
          if (bis.available() >= CHUNK_SIZE) {
            bytesRead = bis.read(originalBuf, 0, CHUNK_SIZE);
          } else {
            originalBuf = new byte[bis.available()];
            bytesRead = bis.read(originalBuf, 0, bis.available());
          }

          // checksums
          originalFileDigest.update(originalBuf);
          chunkDigest.reset();
          chunkDigest.update(originalBuf);
          ChunkManifest cm = new ChunkManifest();
          cm.setCheckSum(chunkDigest.digest());
          cm.setName(originalFile.getName() + CHUNK_EXT + i);
          cm.setSize(bytesRead);

          // TODO remove: Create unencrypted file only in DEBUG mode
          if (LOGGER.isDebugEnabled()) {
            try (BufferedOutputStream bos = new BufferedOutputStream(
                new FileOutputStream(encryptedPath.getPath() + encryptedPath.separator
                    + originalFile.getName() + CHUNK_EXT + i + ".plain"))) {
              bos.write(originalBuf);
            } catch (Exception e) {
              if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
              ;
            }
          }

          // encryption
          ByteArrayInputStream ba_in = new ByteArrayInputStream(originalBuf);
          ByteArrayOutputStream ba_out = new ByteArrayOutputStream();
          heavyChipher.encrypt(ba_in, ba_out);
          chunkDigest.reset();                          // calcilat encrypted chunk checksum
          chunkDigest.update(ba_out.toByteArray());
          cm.setEncCheckSum(chunkDigest.digest());

          // write encrypted chunk
          try (BufferedOutputStream bos = new BufferedOutputStream(
              new FileOutputStream(encryptedPath.getPath() + encryptedPath.separator
                  + lightCipher.encrypt(originalFile.getName() + CHUNK_EXT + i)))) {
            bos.write(ba_out.toByteArray());
          } catch (Exception e) {
            if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
            ;
          }

          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("cm" + i + " " + cm.getName());
            LOGGER.debug("cm" + i + " " + cm.getSize() / 1024);                   // KB
            LOGGER.debug("cm" + i + " " + Utils.bytesToHex(cm.getCheckSum()));
            LOGGER.debug("cm" + i + " " + Utils.bytesToHex(cm.getEncCheckSum()));
          }

          manifest.getChunks().add(cm);
          i++;
        }

        // whole original file checksum
        manifest.setCheckSum(originalFileDigest.digest());
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(originalFile.getName() + " checksum");
          LOGGER.debug(Utils.bytesToHex(manifest.getCheckSum()));
        }
      }

      writeManifest();
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    finally {
      try {
        if (bis != null) bis.close();
      } catch (Exception e) {
        if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
      }
    }
  }

  private void writeManifest() {
    BufferedOutputStream bos = null;

    // -- Write Manifest file through JAXB
    try {
      JAXBContext jc = JAXBContext.newInstance(FileManifest.class);
      Marshaller m = jc.createMarshaller();
      m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
      // TODO remove: Create unencrypted file only in DEBUG mode
      if (LOGGER.isDebugEnabled()) {
        m.marshal(manifest, new File(encryptedPath.getPath()
            + encryptedPath.separator + originalFile.getName() + MANIFEST_EXT + ".plain"));
      }
      // Buffer JAXB XML output
      ByteArrayOutputStream ba_out = new ByteArrayOutputStream();
      m.marshal(manifest, ba_out);
      ByteArrayInputStream ba_in = new ByteArrayInputStream(ba_out.toByteArray());
      // Encrypt manifest file name
      bos = new BufferedOutputStream(new FileOutputStream(encryptedPath.getPath()
          + encryptedPath.separator + lightCipher.encrypt(originalFile.getName() + MANIFEST_EXT)));
      // Encrypt manifest content
      lightCipher.encrypt(ba_in, bos);
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    finally {
      try {
        if (bos != null) bos.close();
      } catch (Exception e) {
        if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
      }
    }
  }

  private void setIVs(byte[] iv0, byte[] iv1) {
    // generate random IVs, update manifest and restart ciphers
    manifest.setIV0(iv0);        // get new IV
    manifest.setIV1(iv1);

    heavyChipher.resetCiphers();
    heavyChipher.setIV0(iv0);
    heavyChipher.setIV(iv1);
    heavyChipher.initCiphers();
  }

  public File getOriginalFile() {
    return originalFile;
  }

  public void setOriginalFile(File originalFile) {
    this.originalFile = originalFile;
  }

  public File getEncryptedPath() {
    return encryptedPath;
  }

  public void setEncryptedPath(File encryptedPath) {
    this.encryptedPath = encryptedPath;
  }
}
