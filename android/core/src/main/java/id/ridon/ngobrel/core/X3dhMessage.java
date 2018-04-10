package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * This class represents X3DH Message
 */

public class X3dhMessage {
  final String infoCipher = Constants.X3DhMessageInfo;
  final PublicKey identity;
  public final PublicKey ephKey;
  public final PreKeyId preKeyId;
  final byte[] message;

  /**
   * Creates a new X3dhMessage with a key and additional data
   * @param identity The identity public key
   * @param ephKey An ephemeral public key
   * @param preKeyId The pre key id
   * @param key A key
   * @param message An plaintext
   * @param ad An additional data
   */
  public X3dhMessage(PublicKey identity, PublicKey ephKey, PreKeyId preKeyId, byte[] key, byte[] message, byte[] ad)  throws EncryptionFailedException {

    this.identity = identity;
    this.ephKey = ephKey;
    this.preKeyId = preKeyId;

    Aead aead = new Aead(key, Constants.X3DhMessageInfo);
    this.message = aead.encrypt(message, ad);
  }

  /**
   * Creates a new X3dhMessage with a key and additional data
   * @param identity The identity public key
   * @param ephKey An ephemeral public key
   * @param preKeyId The pre key id
   * @param message An plaintext
   */
  public X3dhMessage(PublicKey identity, PublicKey ephKey, PreKeyId preKeyId, byte[] message) {
    this.identity = identity;
    this.ephKey = ephKey;
    this.preKeyId = preKeyId;
    this.message = message;
  }

  /**
   * Decrypts a message with a key and an additional data
   * @param key A key
   * @param ad Additional data
   * @return decrypted text
   * @throws IllegalDataSizeException
   * @throws DecryptionFailedException
   * @throws AuthenticationException
   */
  public byte[] decrypt(byte[] key, byte[] ad) throws IllegalDataSizeException, DecryptionFailedException, AuthenticationException {
    Aead aead = new Aead(key, Constants.X3DhMessageInfo);
    return aead.decrypt(message, ad);
  }

  /**
   * Encodes an X3dhMessage
   * @return byte sequence representation of an X3dhMessage
   */
  public byte[] encode() {
    int size = 2 * 33 + // pub keys
        1 + // prekey indicator
        ((preKeyId == null) ? 0 : 32) + //prekey (if any)
        message.length;

    byte[] data = new byte[size];
    int count = 0;
    System.arraycopy(identity.encode(), 0, data, 0, 33);
    count += 33;
    System.arraycopy(ephKey.encode(), 0, data, count, 33);
    count += 33;
    if (preKeyId != null) {
      data[count ++] = 1;
      System.arraycopy(preKeyId.raw(), 0, data, count, 32);
      count += 32;
    } else {
      data[count ++] = 0;
    }
    System.arraycopy(message, 0, data, count, message.length);
    return data;
  }

  /**
   * Decodes a raw data into an X3dhMessage object
   * @param raw data
   * @return an X3dhMessage object
   * @throws IllegalDataSizeException
   * @throws InvalidKeyException
   */
  public static final X3dhMessage decode(byte[] raw) throws IllegalDataSizeException, InvalidKeyException {
    if (raw.length < 99) {
      throw new IllegalDataSizeException();
    }

    int count = 0;
    PublicKey identity = PublicKey.decode(raw, 0);
    count += 33;
    PublicKey ephKey = PublicKey.decode(raw, count);
    count += 33;
    boolean hasPreKeyId = (raw[count ++] == 1);
    PreKeyId preKeyId = null;
    if (hasPreKeyId) {
      preKeyId = new PreKeyId(raw, count);
      count += 32;
    }
    byte[] message = new byte[raw.length - count];
    System.arraycopy(raw, count, message, 0, message.length);
    return new X3dhMessage(identity, ephKey, preKeyId, message);
  }

  static void clearKey(byte[] key) {
    for (int i = 0; i < key.length; i ++) {
      key[i] = 0;
    }
  }

  /**
   * Retrieves a shared key by a sender
   * @param pair A random ephemeral key pair
   * @param me A key bundle owned by sender
   * @param you A key bundle owned by recipient
   * @param info An info string
   * @return A SharedKey object
   */
  public static final SharedKey getSharedKeySender(KeyPair pair, BundlePrivate me, BundlePublic you, String info) throws NoSuchAlgorithmException {
    return getSharedKeySender(pair, me, you, info, null);
  }

    /**
     * Retrieves a shared key by a sender
     * @param pair A random ephemeral key pair
     * @param me A key bundle owned by sender
     * @param you A key bundle owned by recipient
     * @param info An info string
     * @param preKeyId preKeyId
     * @return A SharedKey object
     */
  public static final SharedKey getSharedKeySender(KeyPair pair, BundlePrivate me, BundlePublic you, String info, PreKeyId preKeyId) throws NoSuchAlgorithmException {
    byte[] dh1 = me.identity.shareSecret(you.spk.publicKey);
    byte[] dh2 = pair.privateKey.shareSecret(you.identity);
    byte[] dh3 = pair.privateKey.shareSecret(you.spk.publicKey);

    PreKey preKey = you.fetch(preKeyId);

    byte[] keys;
    int count = 0;
    if (preKeyId != null && preKey != null) {
      byte[] dh4 = pair.privateKey.shareSecret(preKey.publicKey);
      keys = new byte[dh1.length + dh2.length + dh3.length + dh4.length];
      System.arraycopy(dh1, 0, keys, count, dh1.length);
      count += dh1.length;
      System.arraycopy(dh2, 0, keys, count, dh2.length);
      count += dh2.length;
      System.arraycopy(dh3, 0, keys, count, dh3.length);
      count += dh3.length;
      System.arraycopy(dh4, 0, keys, count, dh4.length);
      clearKey(dh1);
      clearKey(dh2);
      clearKey(dh3);
      clearKey(dh4);
    } else {
      keys = new byte[dh1.length + dh2.length + dh3.length];
      System.arraycopy(dh1, 0, keys, count, dh1.length);
      count += dh1.length;
      System.arraycopy(dh2, 0, keys, count, dh2.length);
      count += dh2.length;
      System.arraycopy(dh3, 0, keys, count, dh3.length);

      clearKey(dh1);
      clearKey(dh2);
      clearKey(dh3);
    }

    byte[] salt = Constants.getRidonSalt512();
    Kdf kdf = Kdf.KdfSha512(keys, salt);
    byte[] kdfResult = kdf.get(info, 32);

    SharedKey sk = new SharedKey(kdfResult, preKeyId);

    pair.privateKey.clear();

    return sk;
  }

  /**
   * Retrieves a shared key by a recipient
   * @param me A key bundle owned by the recipient
   * @param you A key bundle owned by the sender
   * @param info An info string
   * @return A shared key
   */
  public static final byte[] getSharedKeyRecipient(PublicKey ephKey, PreKeyId preKeyId, BundlePrivate me, BundlePublic you, String info) throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] dh1 = me.spk.shareSecret(you.identity);
    byte[] dh2 = me.identity.shareSecret(ephKey);
    byte[] dh3 = me.spk.shareSecret(ephKey);

    byte[] keys;
    int count = 0;

    if (preKeyId!= null) {
      PrivateKey oneTimePrivate = me.fetch(preKeyId);

      if (oneTimePrivate != null) {
        byte[] dh4 = oneTimePrivate.shareSecret(ephKey);

        keys = new byte[dh1.length + dh2.length + dh3.length + dh4.length];
        System.arraycopy(dh1, 0, keys, count, dh1.length);
        count += dh1.length;
        System.arraycopy(dh2, 0, keys, count, dh2.length);
        count += dh2.length;
        System.arraycopy(dh3, 0, keys, count, dh3.length);
        count += dh3.length;
        System.arraycopy(dh4, 0, keys, count, dh4.length);
        clearKey(dh1);
        clearKey(dh2);
        clearKey(dh3);
        clearKey(dh4);
      } else {
        throw new InvalidKeyException();
      }
      if (oneTimePrivate != null) {
        oneTimePrivate.clear();
      }

    } else {
      keys = new byte[dh1.length + dh2.length + dh3.length];
      System.arraycopy(dh1, 0, keys, count, dh1.length);
      count += dh1.length;
      System.arraycopy(dh2, 0, keys, count, dh2.length);
      count += dh2.length;
      System.arraycopy(dh3, 0, keys, count, dh3.length);

      clearKey(dh1);
      clearKey(dh2);
      clearKey(dh3);
    }

    byte[] salt = Constants.getRidonSalt512();
    Kdf kdf = Kdf.KdfSha512(keys, salt);
    byte[] kdfResult = kdf.get(info, 32);

    return kdfResult;
  }
}
