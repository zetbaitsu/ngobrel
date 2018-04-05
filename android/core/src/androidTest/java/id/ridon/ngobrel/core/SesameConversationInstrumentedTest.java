package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

@RunWith(AndroidJUnit4.class)
public class SesameConversationInstrumentedTest {
  final String AliceUserId = "+62-222-849-Alice";
  final String BobUserId = "+62-111-948-Bob";

  final String AliceDeviceId1 = "8d74beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac98be";
  final String AliceDeviceId2 = "6g53beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac65he";
  final String BobDeviceId1 = "092fcfbbcfca3b5be7ae1b5e58538e92c35ab273ae13664fed0d67484c8e78a6";
  final String BobDeviceId2 = "6297f7a86e92f27510b0a06b74ef79a7c52b491825b7d7e8af39ebc17aa7143b";

  // This is where the server stores the bundle public of the users
  HashMap<String, BundlePublicCollection> serverBundles = new HashMap<>();

  // Mailboxes
  // Every message is put in an array inside a hashmap of device id and encrypted data
  HashMap<HashId, ArrayList<byte[]>> mailBoxes = new HashMap<>();

  void serverPutToMailbox(byte[] encrypted) throws IOException, InvalidKeyException {
    HashMap<HashId, byte[]> unpacked = SesameConversation.unpackEncrypted(encrypted);
    Set<HashId> hashIds = unpacked.keySet();
    Iterator<HashId> it = hashIds.iterator();
    while (it.hasNext()) {
      HashId id = it.next();
      ArrayList<byte[]> msgList = mailBoxes.get(id);
      if (msgList == null) {
        msgList = new ArrayList<>();
      }
      byte[] data = unpacked.get(id);
      msgList.add(data);
      mailBoxes.put(id, msgList);
    }
  }

  byte[] serverFetchEncrypted(HashId id) {
    ArrayList<byte[]> msgList = mailBoxes.get(id);
    if (msgList == null) {
      msgList = new ArrayList<>();
    }
    if (msgList.size() == 0) {
      return null;
    }
    byte[] data = msgList.get(0);
    if (data != null) {
      msgList.remove(0);
    }
    return data;
  }

  @Test
  public void testEncryptDecrypt() throws Exception {

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(new HashId(AliceDeviceId1.getBytes()), AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(new HashId(AliceDeviceId1.getBytes()), BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(new HashId(BobDeviceId1.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(new HashId(BobDeviceId1.getBytes()), BundlePublic.decode(bobBundlePublicRaw));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Alice wants to send a message to Bob
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    SesameConversation aliceConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceConversation.initializeSender();

    String message = "alice-msg1";

    byte[] decrypted;
    byte[] encrypted = aliceConversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    encrypted = aliceConversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);
    // Server then -- in some way -- tells Bob that he has an incoming message
    // Bob then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    BundlePublicCollection serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob downloads all the messages from bobDevice.id
    while (true) {
      download = serverFetchEncrypted(bobDevice.id);
      if (download == null) {
        break;
      }

      decrypted = bobConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Bob replies back
    message = "bob-msg1-alice-msg1";
    encrypted = bobConversation.encrypt(message.getBytes());

    // And uploads to server
    serverPutToMailbox(encrypted);

    // Alice downloads the messages
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Alice replies back
    message = "alice-msg2";
    encrypted = aliceConversation.encrypt(message.getBytes());

    // Bob downloads the message
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }
  }

  @Test
  public void testEncryptDecryptMultipleMessage() throws Exception {

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(new HashId(AliceDeviceId1.getBytes()), AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(new HashId(AliceDeviceId1.getBytes()), BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(new HashId(BobDeviceId1.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(new HashId(BobDeviceId1.getBytes()), BundlePublic.decode(bobBundlePublicRaw));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Alice wants to send a message to Bob
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    SesameConversation aliceConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceConversation.initializeSender();

    String message1 = "alice-msg1";

    byte[] decrypted;
    byte[] encrypted = aliceConversation.encrypt(message1.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    String message2 = "alice-msg2";
    encrypted = aliceConversation.encrypt(message2.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    // Server then -- in some way -- tells Bob that he has an incoming message
    // Bob then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    BundlePublicCollection serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob downloads all the messages from bobDevice.id
    int count = 0;
    while (true) {
      download = serverFetchEncrypted(bobDevice.id);
      if (download == null) {
        break;
      }

      // Got java.security.InvalidKeyException
      decrypted = bobConversation.decrypt(download);
      if (count == 0) {
        Assert.assertEquals(Arrays.equals(decrypted, message1.getBytes()), true);
      } else {
        Assert.assertEquals(Arrays.equals(decrypted, message2.getBytes()), true);
      }
      count++;
    }
  }

  @Test
  public void testEncryptDecryptMultipleDevice() throws Exception {

    // Alice got a device
    SesameSenderDevice aliceDevice1 = new SesameSenderDevice(new HashId(AliceDeviceId1.getBytes()), AliceUserId);
    SesameSenderDevice aliceDevice2 = new SesameSenderDevice(new HashId(AliceDeviceId2.getBytes()), AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw1 = aliceDevice1.getBundle().bundlePublic.encode();
    byte[] aliceBundlePublicRaw2 = aliceDevice2.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(new HashId(AliceDeviceId1.getBytes()), BundlePublic.decode(aliceBundlePublicRaw1));
    aliceBundlePublicCollection.put(new HashId(AliceDeviceId2.getBytes()), BundlePublic.decode(aliceBundlePublicRaw2));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob has two devices
    SesameSenderDevice bobDevice1 = new SesameSenderDevice(new HashId(BobDeviceId1.getBytes()), BobUserId);
    SesameSenderDevice bobDevice2 = new SesameSenderDevice(new HashId(BobDeviceId2.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw1 = bobDevice1.getBundle().bundlePublic.encode();
    byte[] bobBundlePublicRaw2 = bobDevice2.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(new HashId(BobDeviceId1.getBytes()), BundlePublic.decode(bobBundlePublicRaw1));
    bobBundlePublicCollection.put(new HashId(BobDeviceId2.getBytes()), BundlePublic.decode(bobBundlePublicRaw2));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Alice wants to send a message to Bob
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    SesameConversation alice1Conversation = new SesameConversation(AliceUserId, aliceDevice1.id, aliceDevice1.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    alice1Conversation.initializeSender();

    String message = "alice-msg1";

    byte[] decrypted;
    byte[] encrypted = alice1Conversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    // Server then -- in some way -- tells Bob that he has an incoming message
    // Bob then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    BundlePublicCollection serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation = new SesameConversation(BobUserId, bobDevice2.id, bobDevice2.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob downloads all the messages from bobDevice.id
    while (true) {
      download = serverFetchEncrypted(bobDevice2.id);
      if (download == null) {
        break;
      }

      decrypted = bobConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Bob replies back
    message = "bob-msg1-alice-msg1";
    // Got NPE
    encrypted = bobConversation.encrypt(message.getBytes());

    // And uploads to server
    serverPutToMailbox(encrypted);

    // Alice downloads the messages
    while (true) {
      download = serverFetchEncrypted(aliceDevice1.id);
      if (download == null) {
        break;
      }

      decrypted = alice1Conversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Alice2 sent message to Bob
    SesameConversation alice2Conversation = new SesameConversation(AliceUserId, aliceDevice2.id, aliceDevice2.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    alice2Conversation.initializeSender();

    // Alice replies back
    message = "alice-msg2";
    encrypted = alice2Conversation.encrypt(message.getBytes());

    // And uploads to server
    serverPutToMailbox(encrypted);

    // Bob downloads the message
    while (true) {
      download = serverFetchEncrypted(bobDevice2.id);
      if (download == null) {
        break;
      }

      decrypted = bobConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }
  }

  @Test
  public void testAddingNewDevice() throws Exception {

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(new HashId(AliceDeviceId1.getBytes()), AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(new HashId(AliceDeviceId1.getBytes()), BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // First Bob device
    SesameSenderDevice bobDevice1 = new SesameSenderDevice(new HashId(BobDeviceId1.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw1 = bobDevice1.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    serverBundles.put(BobUserId, new BundlePublicCollection(new HashId(BobDeviceId1.getBytes()), BundlePublic.decode(bobBundlePublicRaw1)));

    // Alice wants to send a message to Bob
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    SesameConversation aliceConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceConversation.initializeSender();

    String message = "alice-msg1";

    byte[] decrypted;
    byte[] encrypted = aliceConversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    // Server then -- in some way -- tells Bob that he has an incoming message
    // Bob then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    BundlePublicCollection serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation1 = new SesameConversation(BobUserId, bobDevice1.id, bobDevice1.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob from first device downloads all the messages
    download = serverFetchEncrypted(bobDevice1.id);
    decrypted = bobConversation1.decrypt(download);
    Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);

    // ------ From here Bob will add new device -----------

    // Second Bob device
    SesameSenderDevice bobDevice2 = new SesameSenderDevice(new HashId(BobDeviceId2.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw2 = bobDevice2.getBundle().bundlePublic.encode();

    // Get current public bundle from server
    BundlePublicCollection bobBundlePublicCollection = serverBundles.get(BobUserId);
    bobBundlePublicCollection.put(new HashId(BobDeviceId2.getBytes()), BundlePublic.decode(bobBundlePublicRaw2));

    // Server then gets it
    // and collect it by it's device id
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Alice wants to send a message to Bob, so she need to reinitialize conversation
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    aliceConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceConversation.initializeSender();

    // Bob from device 2 not have any messages
    download = serverFetchEncrypted(bobDevice2.id);
    Assert.assertEquals(download, null);

    // Alice send message again
    message = "alice-msg2";
    encrypted = aliceConversation.encrypt(message.getBytes());

    // And uploads to server
    serverPutToMailbox(encrypted);

    /*// Bob from device 1 downloads all the messages
    download = serverFetchEncrypted(bobDevice1.id);
    // But this is fail, invalid key, so after bob adding new device, old device cannot be used anymore
    try {
      decrypted = bobConversation1.decrypt(download);
    } catch (Exception e) {
      Assert.assertEquals(e instanceof InvalidKeyException, true);
    }*/

    // Bob from device 1 need to reinitialize conversation too
    serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    bobConversation1 = new SesameConversation(BobUserId, bobDevice1.id, bobDevice1.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob from device 1 downloads all the messages
    download = serverFetchEncrypted(bobDevice1.id);
    // Got id.ridon.ngobrel.core.AuthenticationException
    decrypted = bobConversation1.decrypt(download);
    Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);

    // Server then -- in some way -- tells Bob from device 2 that he has an incoming message
    // Bob from device 2 then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation2 = new SesameConversation(BobUserId, bobDevice2.id, bobDevice2.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob from device 2 downloads all the messages
    download = serverFetchEncrypted(bobDevice2.id);
    decrypted = bobConversation2.decrypt(download);
    Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
  }
}