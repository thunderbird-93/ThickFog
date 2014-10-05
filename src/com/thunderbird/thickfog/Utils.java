package com.thunderbird.thickfog;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.SecureRandom;
import java.util.Map;

public abstract class Utils {
  final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
  final private static Logger LOGGER = LoggerFactory.getLogger(Utils.class);
  private static SecureRandom sr = null;

  /**
   * Generate SecureRandom byte array
   * @param length of data returned
   * @return byte array with random data
   */
  public static byte[] getSecureRandom(int length) {
    byte[] buf = null;
    try {
      if (sr == null) sr = SecureRandom.getInstance("SHA1PRNG", "SUN");     // initialize only one instance
      if (length > 0) {
        buf = new byte[length];
        sr.nextBytes(buf);
      }
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error("", e);
    }
    return buf;
  }

  /**
   * Removes Java cryptographic restriction, (specifically on key length)
   */
  public static void removeCryptographyRestrictions() {
    if (!isRestrictedCryptography()) {
      if (LOGGER.isDebugEnabled()) LOGGER.debug("Cryptography restrictions removal not needed");
      return;
    }
    try {
      /*
       * Do the following, but with reflection to bypass access checks:
       *
       * JceSecurity.isRestricted = false;
       * JceSecurity.defaultPolicy.perms.clear();
       * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
       */
      final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
      final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
      final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

      final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
      isRestrictedField.setAccessible(true);
      isRestrictedField.set(null, false);

      final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
      defaultPolicyField.setAccessible(true);
      final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

      final Field perms = cryptoPermissions.getDeclaredField("perms");
      perms.setAccessible(true);
      ((Map<?, ?>) perms.get(defaultPolicy)).clear();

      final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
      instance.setAccessible(true);
      defaultPolicy.add((Permission) instance.get(null));

      if (LOGGER.isDebugEnabled()) LOGGER.debug("Successfully removed cryptography restrictions");
    } catch (final Exception e) {
      if (LOGGER.isErrorEnabled()) LOGGER.error(e.getLocalizedMessage(), e);
    }
  }

  private static boolean isRestrictedCryptography() {
    // This simply matches the Oracle JRE, but not OpenJDK.
    return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
  }

  /**
   * Converts Byte Array to Hex string representation
   * @param bytes - source byte array
   * @return - string with hex representation of byte array
   */
  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  /**
   * Converts Hex string to Byte Array
   * @param s - string containing hex data representation to convert
   * @return - byte array containing hex data
   */
  public static byte[] hexToBytes(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
          + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }

  public static String base62encode(byte[] data) {
    String base64 = Base64.encode(data);
    return base64ToBase62(base64);
  }

  public static byte[] base62decode(String base62) throws Base64DecodingException {
    String base64 = base62ToBase64(base62);
    return Base64.decode(base64);
  }

  /**
   * Convert Base64 to Base62 so it's filename safe
   * @param base64 - input Base64 string
   * @return - resulting Base62 string
   */
  private static String base64ToBase62(String base64) {
    StringBuilder buf = new StringBuilder(base64.length() * 2);

    for (int i = 0; i < base64.length(); i++) {
      char ch = base64.charAt(i);
      switch (ch) {
        case 'i':
          buf.append("ii");
          break;
        case '+':
          buf.append("ip");
          break;
        case '/':
          buf.append("is");
          break;
        case '=':
          buf.append("ie");
          break;
        case '\n':
          break;
        default:
          buf.append(ch);
      }
    }
    return buf.toString();
  }

  /**
   * Convert Base62 to Base64
   * @param base62 - input Base62 string
   * @return - resulting Base64 string
   */
  private static String base62ToBase64(String base62) {
    StringBuilder buf = new StringBuilder(base62.length());

    int i = 0;
    while (i < base62.length()) {
      char ch = base62.charAt(i);

      if (ch == 'i') {
        i++;
        char code = base62.charAt(i);
        switch (code) {
          case 'i':
            buf.append('i');
            break;
          case 'p':
            buf.append('+');
            break;
          case 's':
            buf.append('/');
            break;
          case 'e':
            buf.append('=');
            break;
          default:
            throw new IllegalStateException("Illegal code in base62 encoding");
        }
      } else {
        buf.append(ch);
      }
      i++;
    }
    return buf.toString();
  }
}