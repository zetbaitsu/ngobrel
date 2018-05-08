package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

@RunWith(AndroidJUnit4.class)
public class GroupConversationInstrumentedTest {
  final String AliceUserId = "+62-222-849-Alice";
  final String BobUserId = "+62-111-948-Bob";
  final String CharlieUserId = "+62-333-489-Charlie";
  final String DaveUserId = "+62-444-249-Dave";

  final HashId AliceDeviceId1 = HashId.random();
  final HashId AliceDeviceId2 = HashId.random();

  final HashId BobDeviceId1 = HashId.random();
  final HashId BobDeviceId2 = HashId.random();

  final HashId CharlieDeviceId1 = HashId.random();
  final HashId DaveDeviceId1 = HashId.random();

  // This is where the server stores the bundle public of the users
  HashMap<String, BundlePublicCollection> serverBundles = new HashMap<>();

  // This is where the server stores the group
  HashMap<HashId, ArrayList<String>> serverGroups = new HashMap<>();

  // Mailboxes
  // Every message is put in an array inside a hashmap of device id and encrypted data
  HashMap<HashId, ArrayList<byte[]>> mailBoxes = new HashMap<>();

  // Group messages are stored here. In real life, the server should put additional effort such as
  // to take note of the received status of each messages for each member of the group.
  HashMap<HashId, ArrayList<byte[]>> groupMessages = new HashMap<>();

  public GroupConversationInstrumentedTest() throws NoSuchAlgorithmException, InvalidKeyException {
  }

  // Register group
  HashId serverRegisterGroup() throws NoSuchAlgorithmException, InvalidKeyException {
    HashId id = HashId.random();
    return id;
  }

  void serverPutToGroup(HashId groupId, byte[] encrypted) {
    ArrayList<byte[]> list = groupMessages.get(groupId);
    if (list == null) {
      list = new ArrayList<>();
    }
    list.add(encrypted);
    groupMessages.put(groupId, list);
  }

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
    mailBoxes.put(id, msgList);
    return data;
  }

  @Test
  public void testEncryptDecrypt() throws Exception {


    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(AliceDeviceId1, AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(AliceDeviceId1, BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(BobDeviceId1, BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(BobDeviceId1, BundlePublic.decode(bobBundlePublicRaw));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Also does Charlie
    SesameSenderDevice charlieDevice = new SesameSenderDevice(CharlieDeviceId1, CharlieUserId);

    // and uploads his
    byte[] charlieBundlePublicRaw = charlieDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection charlieBundlePublicCollection = new BundlePublicCollection(CharlieDeviceId1, BundlePublic.decode(charlieBundlePublicRaw));
    serverBundles.put(CharlieUserId, charlieBundlePublicCollection);

    byte[] encrypted, decrypted;

    // ======================================== ALICE's side of story ===================================================
    // Alice creates a group containing Alice, Bob, and Charlie
    // 1. Alice registers a group in the server
    // This is implementation dependent and not covered here

    HashId aliceGroupId = serverRegisterGroup();

    // 2. Alice must be able to send message to Bob and Charlie,
    //    so she must have a ready conversation with all of the member of the group
    // 2.a.1 She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBobBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBobBundlePublicCollection.encode();

    // 2.a.2 Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // 2.a.3 Alice starts a conversation with Bob
    SesameConversation aliceBobConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceBobConversation.initializeSender();

    // 2.b.1 She downloads Charlie's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceCharlieBundlePublicCollection = serverBundles.get(CharlieUserId);
    download = serverAliceCharlieBundlePublicCollection.encode();

    // 2.b.2 Alice got Charlie's bundle public
    BundlePublicCollection aliceCharlieBundlePublicCollection = BundlePublicCollection.decode(download);

    // 2.b.3 Alice starts a conversation with Charlie
    SesameConversation aliceCharlieConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), CharlieUserId, aliceCharlieBundlePublicCollection);
    aliceCharlieConversation.initializeSender();

    // 3. At this moment, Alice has her own copy of the GroupConversation object
    // 3.1 She creates her sender key
    GroupConversation aliceGroup = new GroupConversation();
    aliceGroup.initSender(AliceDeviceId1);
    MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());

    // 3.2 And sends it to all of group participants
    // First to Bob
    encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And to Charlie
    encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And alice keeps the sender key for herself, so she can read whatever she sent to the group
    aliceGroup.initRecipient(aliceSenderKeyPayload.contents);

    // That's it for setting up a group conversation.
    // Next she can send her first message to the group
    byte[] message = "Welcome".getBytes();

    encrypted = aliceGroup.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // == BOB's story ===============================================================================================
    // Bob gets an information from server that he's been added to a group which was created by Alice
    // It means:
    // 1. He's expecting senderKey from Alice, which means he's creating a receiver side of SesameConversation
    //    or reuse the conversation if it is already created in past time
    BundlePublicCollection serverBobAliceBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobAliceBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobAliceConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    MessageExamplePayload payload = null;
    download = serverFetchEncrypted(bobDevice.id);

    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation bobAliceGroupConversation = new GroupConversation();
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Bob must know which messages he's not yet got from the server
    // This must not in form of integer, a message ID-like form would do
    // As long as it is kept in some records and no message is skipped
    int bobAliceGroupIndex = 0;

    byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

    Assert.assertArrayEquals(decrypted, message);

    // Then Bob wants to reply
    // First he must generate his senderKey
    bobAliceGroupConversation.initSender(BobDeviceId1);

    MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());

    // And he must send it to both Alice and Charlie.
    // He had a conversation with Alice, and he can just send it
    encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // but not with Charlie, so he must initiate conversation with Charlie
    BundlePublicCollection serverBobCharlieBundlePublicCollection = serverBundles.get(CharlieUserId);
    download = serverBobCharlieBundlePublicCollection.encode();
    BundlePublicCollection bobCharlieBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobCharlieConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), CharlieUserId, bobCharlieBundlePublicCollection);
    bobCharlieConversation.initializeSender();

    // and send it to server
    encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // After that, Bob can start to send messages to the group
    message = "Hello from Bob".getBytes();
    encrypted = bobAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice reads the message

    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      // Before decrypting, alice initialize the sender key from the payload
      aliceGroup.initRecipient(payload.contents);
    }

    int aliceAliceGroupIndex = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);


    // == Charlie's story ===============================================================================================
    // Charlie gets an information from server that he's been added to a group which was created by Alice
    // It means:
    // 1. He's expecting senderKey from Alice, which means he's creating a receiver side of SesameConversation
    //    or reuse the conversation if it is already created in past time
    BundlePublicCollection serverCharlieAliceBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverCharlieAliceBundlePublicCollection.encode();
    BundlePublicCollection charlieAliceBundlePublicCollection = BundlePublicCollection.decode(download);
    SesameConversation charlieAliceConversation = new SesameConversation(CharlieUserId, charlieDevice.id, charlieDevice.getBundle(), AliceUserId, charlieAliceBundlePublicCollection);

    BundlePublicCollection serverCharlieBobBundlePublicCollection = serverBundles.get(BobUserId);
    download = serverCharlieBobBundlePublicCollection.encode();
    BundlePublicCollection charlieBobBundlePublicCollection = BundlePublicCollection.decode(download);
    SesameConversation charlieBobConversation = new SesameConversation(CharlieUserId, charlieDevice.id, charlieDevice.getBundle(), BobUserId, charlieBobBundlePublicCollection);

    GroupConversation charlieAliceGroupConversation = new GroupConversation();

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // This one is from Bob
    // In real life, you should do this differently
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    int charlieAliceGroupIndex = 0;
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

  }

  private byte[] serverGetFromGroup(HashId aliceGroupId, int i) {
    ArrayList<byte[]> group = groupMessages.get(aliceGroupId);
    return group.get(i);
  }


  /**
   * This tests a scenario when a new member ("Dave") was added to the group. The actual mechanism
   * of adding someone to the group, either by joining by clicking a link, or
   * got some form of invitation or added directly to the group is outside the scope
   * of the protocol. The implementor is free to do such mechanisms.
   * @throws Exception
   */
  @Test
  public void testEncryptDecryptAddNewMember() throws Exception {
    SesameSenderDevice aliceDevice = initDevice(AliceDeviceId1, AliceUserId);
    SesameSenderDevice bobDevice = initDevice(BobDeviceId1, BobUserId);
    SesameSenderDevice charlieDevice = initDevice(CharlieDeviceId1, CharlieUserId);

    byte[] encrypted, decrypted, download;

    // ======================================== ALICE's side of story ===================================================
    HashId aliceGroupId = serverRegisterGroup();

    SesameConversation aliceBobConversation = establishConversation(AliceUserId, aliceDevice, BobUserId);
    aliceBobConversation.initializeSender();

    SesameConversation aliceCharlieConversation = establishConversation(AliceUserId, aliceDevice, CharlieUserId);
    aliceCharlieConversation.initializeSender();

    GroupConversation aliceGroup = new GroupConversation();
    aliceGroup.initSender(AliceDeviceId1);
    MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());

    // Alice sends senderKey
    encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And alice keeps the sender key for herself, so she can read whatever she sent to the group
    aliceGroup.initRecipient(aliceSenderKeyPayload.contents);

    // That's it for setting up a group conversation.
    // Next she can send her first message to the group
    byte[] message = "Welcome".getBytes();

    encrypted = aliceGroup.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // == BOB's story ===============================================================================================

    SesameConversation bobAliceConversation = establishConversation(BobUserId, bobDevice, AliceUserId);

    MessageExamplePayload payload = null;
    download = serverFetchEncrypted(bobDevice.id);

    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation bobAliceGroupConversation = new GroupConversation();
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Bob must know which messages he's not yet got from the server
    // In real life, this must not in form of integer, a message ID-like form would do
    // As long as it is kept in some records and no message is skipped
    int bobAliceGroupIndex = 0;

    byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

    Assert.assertArrayEquals(decrypted, message);

    // Then Bob wants to reply
    // First he must generate his senderKey
    bobAliceGroupConversation.initSender(BobDeviceId1);

    MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
    bobAliceGroupConversation.initRecipient(bobSenderKeyPayload.contents);

    // And he must send it to both Alice and Charlie.
    // He had a conversation with Alice, and he can just send it
    encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // but not with Charlie, so he must initiate conversation with Charlie
    SesameConversation bobCharlieConversation = establishConversation(BobUserId, bobDevice, CharlieUserId);
    bobCharlieConversation.initializeSender();

    // and send it to server
    encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // After that, Bob can start to send messages to the group
    message = "Hello from Bob".getBytes();
    encrypted = bobAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice reads the message
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      // Before decrypting, alice initialize the sender key from the payload
      aliceGroup.initRecipient(payload.contents);
    }

    int aliceAliceGroupIndex = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);


    // == Charlie's story ===============================================================================================
    SesameConversation charlieAliceConversation = establishConversation(CharlieUserId, charlieDevice, AliceUserId);
    SesameConversation charlieBobConversation = establishConversation(CharlieUserId, charlieDevice, BobUserId);

    GroupConversation charlieAliceGroupConversation = new GroupConversation();

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // This one is from Bob
    // In real life, you should do this differently (e.g. this should happen in an event handler)
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    int charlieAliceGroupIndex = 0;
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

    // ********************************** Dave joins in
    SesameSenderDevice daveDevice = initDevice(DaveDeviceId1, DaveUserId);

    SesameConversation daveAliceConversation = establishConversation(DaveUserId, daveDevice, AliceUserId);
    SesameConversation daveBobConversation = establishConversation(DaveUserId, daveDevice, BobUserId);
    SesameConversation daveCharlieConversation = establishConversation(DaveUserId, daveDevice, CharlieUserId);

    daveAliceConversation.initializeSender();
    daveBobConversation.initializeSender();
    daveCharlieConversation.initializeSender();

    GroupConversation daveAliceGroupConversation = new GroupConversation();
    daveAliceGroupConversation.initSender(DaveDeviceId1);
    MessageExamplePayload daveSenderKeyPayload = new MessageExamplePayload(daveAliceGroupConversation.getSenderKey());
    // Dave sends out his sender key
    encrypted = daveAliceConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    encrypted = daveBobConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    encrypted = daveCharlieConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // Dave sends message
    message = "Dave rules!".getBytes();

    encrypted = daveAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice establish connection with Dave
    SesameConversation aliceDaveConversation = establishConversation(AliceUserId, aliceDevice, DaveUserId);

    download = serverFetchEncrypted(aliceDevice.id);
    decrypted = aliceDaveConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    // Alice confirms that she received Dave's sender key
    aliceGroup.initRecipient(payload.contents);

    // Get next message from server
    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Dave sent to the group
    Assert.assertArrayEquals(decrypted, "Dave rules!".getBytes());

    // Bob establish connection with Dave
    SesameConversation bobDaveConversation = establishConversation(BobUserId, bobDevice, DaveUserId);

    download = serverFetchEncrypted(bobDevice.id);
    decrypted = bobDaveConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    // Alice confirms that she received Dave's sender key
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Get next message from server
    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(download);
    // This was the first message Bob sent to the group
    Assert.assertArrayEquals(decrypted, "Hello from Bob".getBytes());

    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(download);

    // And this is the first message Dave sent to the group
    Assert.assertArrayEquals(decrypted, "Dave rules!".getBytes());

  }

  /**
   * This tests a scenario when a member is removed from the group.
   * The actual mechanism of how a member is removed is out of the scope of
   * the protocol. The concept of removal is that all members of the
   * group have to reset their own sender key when a removal is
   * performed. One way of doing this could be the server sends a signal
   * to the members that somebody is removed from the group, therefore
   * they need to reset the sender key.
   * @throws Exception
   */
  @Test
  public void testEncryptDecryptRemoveMember() throws Exception {
    SesameSenderDevice aliceDevice = initDevice(AliceDeviceId1, AliceUserId);
    SesameSenderDevice bobDevice = initDevice(BobDeviceId1, BobUserId);
    SesameSenderDevice charlieDevice = initDevice(CharlieDeviceId1, CharlieUserId);

    byte[] encrypted, decrypted, download;

    // ======================================== ALICE's side of story ===================================================
    HashId aliceGroupId = serverRegisterGroup();

    SesameConversation aliceBobConversation = establishConversation(AliceUserId, aliceDevice, BobUserId);
    aliceBobConversation.initializeSender();

    SesameConversation aliceCharlieConversation = establishConversation(AliceUserId, aliceDevice, CharlieUserId);
    aliceCharlieConversation.initializeSender();

    GroupConversation aliceGroup = new GroupConversation();
    aliceGroup.initSender(AliceDeviceId1);
    MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());

    // Alice sends senderKey
    encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And alice keeps the sender key for herself, so she can read whatever she sent to the group
    aliceGroup.initRecipient(aliceSenderKeyPayload.contents);

    // That's it for setting up a group conversation.
    // Next she can send her first message to the group
    byte[] message = "Welcome".getBytes();

    encrypted = aliceGroup.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // == BOB's story ===============================================================================================

    SesameConversation bobAliceConversation = establishConversation(BobUserId, bobDevice, AliceUserId);

    MessageExamplePayload payload = null;
    download = serverFetchEncrypted(bobDevice.id);

    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation bobAliceGroupConversation = new GroupConversation();
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Bob must know which messages he's not yet got from the server
    // In real life, this must not in form of integer, a message ID-like form would do
    // As long as it is kept in some records and no message is skipped
    int bobAliceGroupIndex = 0;

    byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

    Assert.assertArrayEquals(decrypted, message);

    // Then Bob wants to reply
    // First he must generate his senderKey
    bobAliceGroupConversation.initSender(BobDeviceId1);

    MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
    bobAliceGroupConversation.initRecipient(bobSenderKeyPayload.contents);

    // And he must send it to both Alice and Charlie.
    // He had a conversation with Alice, and he can just send it
    encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // but not with Charlie, so he must initiate conversation with Charlie
    SesameConversation bobCharlieConversation = establishConversation(BobUserId, bobDevice, CharlieUserId);
    bobCharlieConversation.initializeSender();

    // and send it to server
    encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // After that, Bob can start to send messages to the group
    message = "Hello from Bob".getBytes();
    encrypted = bobAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice reads the message
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      // Before decrypting, alice initialize the sender key from the payload
      aliceGroup.initRecipient(payload.contents);
    }

    int aliceAliceGroupIndex = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);


    // == Charlie's story ===============================================================================================
    SesameConversation charlieAliceConversation = establishConversation(CharlieUserId, charlieDevice, AliceUserId);
    SesameConversation charlieBobConversation = establishConversation(CharlieUserId, charlieDevice, BobUserId);

    GroupConversation charlieAliceGroupConversation = new GroupConversation();

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // This one is from Bob
    // In real life, you should do this differently (e.g. this should happen in an event handler)
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    int charlieAliceGroupIndex = 0;
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

    // ********************************** Dave joins in
    SesameSenderDevice daveDevice = initDevice(DaveDeviceId1, DaveUserId);

    SesameConversation daveAliceConversation = establishConversation(DaveUserId, daveDevice, AliceUserId);
    SesameConversation daveBobConversation = establishConversation(DaveUserId, daveDevice, BobUserId);
    SesameConversation daveCharlieConversation = establishConversation(DaveUserId, daveDevice, CharlieUserId);

    daveAliceConversation.initializeSender();
    daveBobConversation.initializeSender();
    daveCharlieConversation.initializeSender();

    GroupConversation daveAliceGroupConversation = new GroupConversation();
    daveAliceGroupConversation.initSender(DaveDeviceId1);
    MessageExamplePayload daveSenderKeyPayload = new MessageExamplePayload(daveAliceGroupConversation.getSenderKey());
    // Dave sends out his sender key
    encrypted = daveAliceConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    encrypted = daveBobConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    encrypted = daveCharlieConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // Dave sends message
    message = "Dave rules!".getBytes();

    encrypted = daveAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice establish connection with Dave
    SesameConversation aliceDaveConversation = establishConversation(AliceUserId, aliceDevice, DaveUserId);

    download = serverFetchEncrypted(aliceDevice.id);
    decrypted = aliceDaveConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    // Alice confirms that she received Dave's sender key
    aliceGroup.initRecipient(payload.contents);

    // Get next message from server
    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Dave sent to the group
    Assert.assertArrayEquals(decrypted, "Dave rules!".getBytes());

    // Bob establish connection with Dave
    SesameConversation bobDaveConversation = establishConversation(BobUserId, bobDevice, DaveUserId);

    download = serverFetchEncrypted(bobDevice.id);
    decrypted = bobDaveConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    // Alice confirms that she received Dave's sender key
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Get next message from server
    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(download);
    // This was the first message Bob sent to the group
    Assert.assertArrayEquals(decrypted, "Hello from Bob".getBytes());

    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(download);

    // And this is the first message Dave sent to the group
    Assert.assertArrayEquals(decrypted, "Dave rules!".getBytes());

    // Before going to the next step
    // Let's flush all the messages from the server
    // This one is a sender key message for Charlie from Dave
    // We don't need it in this example
    download = serverFetchEncrypted(charlieDevice.id);
    // Dave sent a message which supposed to be read by charlie
    // lets skip this for a moment
    charlieAliceGroupIndex++;

    // ====================================================================
    // Meat of the test:
    // Let's imagine that Bob is removed

    // Alice, Charlie, and Dave needs to do initSender again
    // and send out their new sender key to all remaining members
    aliceGroup.initSender(AliceDeviceId1);
    aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());
    encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    encrypted = aliceDaveConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    charlieAliceGroupConversation.initSender(CharlieDeviceId1);
    MessageExamplePayload charlieSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
    encrypted = charlieAliceConversation.encrypt(charlieSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);


    daveAliceGroupConversation.initSender(DaveDeviceId1);
    daveSenderKeyPayload = new MessageExamplePayload(daveAliceGroupConversation.getSenderKey());

    encrypted = daveAliceConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    encrypted = daveCharlieConversation.encrypt(daveSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And all the members need to reinit their GroupConversation object
    download = serverFetchEncrypted(aliceDevice.id);
    decrypted = aliceCharlieConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 2);
    aliceGroup.initRecipient(payload.contents);

    download = serverFetchEncrypted(aliceDevice.id);
    decrypted = aliceDaveConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 2);
    aliceGroup.initRecipient(payload.contents);

    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 2);
    charlieAliceGroupConversation.initRecipient(payload.contents);

    SesameConversation charlieDaveConversation = establishConversation(CharlieUserId, charlieDevice, DaveUserId);

    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieDaveConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 2);
    charlieAliceGroupConversation.initRecipient(payload.contents);

    encrypted = charlieDaveConversation.encrypt(charlieSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);


    // Dave sends message
    message = "Dave rules again!".getBytes();

    encrypted = daveAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Now we can see that Bob is no longer able to read the message
    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    boolean bobCheck = true;
    try {
      decrypted = bobAliceGroupConversation.decrypt(download);
    } catch (Exception e) {
      bobCheck = false;
    }

    Assert.assertEquals(bobCheck, false);

    // But Charlie can still read it
    // for sake of simplicity we skip the message which was sent by Dave earlier
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

    // So can alice
    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

  }

  // This tests a scenario where Bob changes his bundle
  // The concept is Bob must send out his new sender key to all members
  // and all members must send out their sender key to the new Bob
  @Test
  public void testEncryptDecryptBobChangesBundle() throws Exception {
      SesameSenderDevice aliceDevice = initDevice(AliceDeviceId1, AliceUserId);
      SesameSenderDevice bobDevice = initDevice(BobDeviceId1, BobUserId);
      SesameSenderDevice charlieDevice = initDevice(CharlieDeviceId1, CharlieUserId);

      byte[] encrypted, decrypted, download;

      // ======================================== ALICE's side of story ===================================================
      HashId aliceGroupId = serverRegisterGroup();

      SesameConversation aliceBobConversation = establishConversation(AliceUserId, aliceDevice, BobUserId);
      aliceBobConversation.initializeSender();

      SesameConversation aliceCharlieConversation = establishConversation(AliceUserId, aliceDevice, CharlieUserId);
      aliceCharlieConversation.initializeSender();

      GroupConversation aliceGroup = new GroupConversation();
      aliceGroup.initSender(AliceDeviceId1);
      MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());

      // Alice sends senderKey
      encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);
      encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);

      // And alice keeps the sender key for herself, so she can read whatever she sent to the group
      aliceGroup.initRecipient(aliceSenderKeyPayload.contents);

      // That's it for setting up a group conversation.
      // Next she can send her first message to the group
      byte[] message = "Welcome".getBytes();

      encrypted = aliceGroup.encrypt(message);
      serverPutToGroup(aliceGroupId, encrypted);

      // == BOB's story ===============================================================================================

      SesameConversation bobAliceConversation = establishConversation(BobUserId, bobDevice, AliceUserId);

      MessageExamplePayload payload = null;
      download = serverFetchEncrypted(bobDevice.id);

      decrypted = bobAliceConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      GroupConversation bobAliceGroupConversation = new GroupConversation();
      bobAliceGroupConversation.initRecipient(payload.contents);

      // Bob must know which messages he's not yet got from the server
      // In real life, this must not in form of integer, a message ID-like form would do
      // As long as it is kept in some records and no message is skipped
      int bobAliceGroupIndex = 0;

      byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
      decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

      Assert.assertArrayEquals(decrypted, message);

      // Then Bob wants to reply
      // First he must generate his senderKey
      bobAliceGroupConversation.initSender(BobDeviceId1);

      MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
      bobAliceGroupConversation.initRecipient(bobSenderKeyPayload.contents);

      // And he must send it to both Alice and Charlie.
      // He had a conversation with Alice, and he can just send it
      encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);

      // but not with Charlie, so he must initiate conversation with Charlie
      SesameConversation bobCharlieConversation = establishConversation(BobUserId, bobDevice, CharlieUserId);
      bobCharlieConversation.initializeSender();

      // and send it to server
      encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);

      // After that, Bob can start to send messages to the group
      message = "Hello from Bob".getBytes();
      encrypted = bobAliceGroupConversation.encrypt(message);
      serverPutToGroup(aliceGroupId, encrypted);

      // Alice reads the message
      while (true) {
          download = serverFetchEncrypted(aliceDevice.id);
          if (download == null) {
              break;
          }

          decrypted = aliceBobConversation.decrypt(download);
          payload = MessageExamplePayload.decode(decrypted);
          // Check whether this is a sender key message
          Assert.assertEquals(payload.type, 2);

          // Before decrypting, alice initialize the sender key from the payload
          aliceGroup.initRecipient(payload.contents);
      }

      int aliceAliceGroupIndex = 0;

      download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
      decrypted = aliceGroup.decrypt(download);

      // This is the first message Alice sent to the group
      Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

      download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
      decrypted = aliceGroup.decrypt(download);

      // And this is the second message, coming from Bob
      Assert.assertArrayEquals(decrypted, message);


      // == Charlie's story ===============================================================================================
      SesameConversation charlieAliceConversation = establishConversation(CharlieUserId, charlieDevice, AliceUserId);
      SesameConversation charlieBobConversation = establishConversation(CharlieUserId, charlieDevice, BobUserId);

      GroupConversation charlieAliceGroupConversation = new GroupConversation();

      // Get the first private message, came from Alice
      download = serverFetchEncrypted(charlieDevice.id);
      decrypted = charlieAliceConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      charlieAliceGroupConversation.initRecipient(payload.contents);

      // This one is from Bob
      // In real life, you should do this differently (e.g. this should happen in an event handler)
      download = serverFetchEncrypted(charlieDevice.id);
      decrypted = charlieBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      charlieAliceGroupConversation.initRecipient(payload.contents);

      int charlieAliceGroupIndex = 0;
      download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
      decrypted = charlieAliceGroupConversation.decrypt(download);

      Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

      download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
      decrypted = charlieAliceGroupConversation.decrypt(download);

      Assert.assertArrayEquals(decrypted, message);

      // ------------------------------------------------------------------
      // Bob changes bundle
      // What he needs to do is just reinit the device and generate a new
      // sender key and broadcasts it to all members
      bobDevice = initDevice(BobDeviceId1, BobUserId);
      bobAliceGroupConversation.initSender(BobDeviceId1);
      bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
      encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);

      encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);

      // Then in some way, Bob broadcasts that the bundle is changed
      // so Alice and Charlie can send their sender key
      // we only do it for Alice in this example for simplicity
      aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());
      encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
      serverPutToMailbox(encrypted);

      // Then the broadcast is received by each Alice and Charlie
      download = serverFetchEncrypted(aliceDevice.id);
      decrypted = aliceBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      Assert.assertEquals(payload.type, 2);
      aliceGroup.initRecipient(payload.contents);

      download = serverFetchEncrypted(charlieDevice.id);
      decrypted = charlieBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      Assert.assertEquals(payload.type, 2);
      charlieAliceGroupConversation.initRecipient(payload.contents);

      // Bob also gets Alice latest sender key
      download = serverFetchEncrypted(bobDevice.id);
      decrypted = bobAliceConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      Assert.assertEquals(payload.type, 2);
      bobAliceGroupConversation.initRecipient(payload.contents);

      // THen alice sends a message to the group
      message = "Hello again".getBytes();
      encrypted = aliceGroup.encrypt(message);
      serverPutToGroup(aliceGroupId, encrypted);

      // A new Bob can read the message
      bobAliceGroupIndex++;
      download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
      decrypted = bobAliceGroupConversation.decrypt(download);
      Assert.assertArrayEquals(decrypted, "Hello again".getBytes());
  }

  // This tests a scenario where Bob add new device
  // The concept is Bob must send out his new sender key to all members
  // and all members must send out their sender key to the new Bob
  @Test
  public void testEncryptDecryptBobAddNewDevice() throws Exception {
    SesameSenderDevice aliceDevice = initDevice(AliceDeviceId1, AliceUserId);
    SesameSenderDevice bobDevice = initDevice(BobDeviceId1, BobUserId);
    SesameSenderDevice charlieDevice = initDevice(CharlieDeviceId1, CharlieUserId);

    byte[] encrypted, decrypted, download;

    // ======================================== ALICE's side of story ===================================================
    HashId aliceGroupId = serverRegisterGroup();

    SesameConversation aliceBobConversation = establishConversation(AliceUserId, aliceDevice, BobUserId);
    aliceBobConversation.initializeSender();

    SesameConversation aliceCharlieConversation = establishConversation(AliceUserId, aliceDevice, CharlieUserId);
    aliceCharlieConversation.initializeSender();

    GroupConversation aliceGroup = new GroupConversation();
    aliceGroup.initSender(AliceDeviceId1);
    MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());

    // Alice sends senderKey
    encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And alice keeps the sender key for herself, so she can read whatever she sent to the group
    aliceGroup.initRecipient(aliceSenderKeyPayload.contents);

    // That's it for setting up a group conversation.
    // Next she can send her first message to the group
    byte[] message = "Welcome".getBytes();

    encrypted = aliceGroup.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // == BOB's story ===============================================================================================

    SesameConversation bobAliceConversation = establishConversation(BobUserId, bobDevice, AliceUserId);

    MessageExamplePayload payload = null;
    download = serverFetchEncrypted(bobDevice.id);

    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation bobAliceGroupConversation = new GroupConversation();
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Bob must know which messages he's not yet got from the server
    // In real life, this must not in form of integer, a message ID-like form would do
    // As long as it is kept in some records and no message is skipped
    int bobAliceGroupIndex = 0;

    byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);

    decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

    Assert.assertArrayEquals(decrypted, message);

    // Then Bob wants to reply
    // First he must generate his senderKey
    bobAliceGroupConversation.initSender(BobDeviceId1);

    MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
    bobAliceGroupConversation.initRecipient(bobSenderKeyPayload.contents);

    // And he must send it to both Alice and Charlie.
    // He had a conversation with Alice, and he can just send it
    encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // but not with Charlie, so he must initiate conversation with Charlie
    SesameConversation bobCharlieConversation = establishConversation(BobUserId, bobDevice, CharlieUserId);
    bobCharlieConversation.initializeSender();

    // and send it to server
    encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // After that, Bob can start to send messages to the group
    // BobMsg1
    message = "Hello from Bob".getBytes();
    encrypted = bobAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice reads the message
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      // Before decrypting, alice initialize the sender key from the payload
      aliceGroup.initRecipient(payload.contents);
    }

    int aliceAliceGroupIndex = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);


    // == Charlie's story ===============================================================================================
    SesameConversation charlieAliceConversation = establishConversation(CharlieUserId, charlieDevice, AliceUserId);
    SesameConversation charlieBobConversation = establishConversation(CharlieUserId, charlieDevice, BobUserId);

    GroupConversation charlieAliceGroupConversation = new GroupConversation();

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // This one is from Bob
    // In real life, you should do this differently (e.g. this should happen in an event handler)
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    int charlieAliceGroupIndex = 0;
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

    // ------------------------------------------------------------------
    // Bob add a new device
    // What he needs to do is just reinit the device and generate a new
    // sender key and broadcasts it to all members
    SesameSenderDevice bobDevice2 = new SesameSenderDevice(BobDeviceId2, BobUserId);
    byte[] bundlePublicRaw = bobDevice2.getBundle().bundlePublic.encode();
    BundlePublicCollection bundlePublicCollection = serverBundles.get(BobUserId);
    bundlePublicCollection.put(BobDeviceId2, BundlePublic.decode(bundlePublicRaw));
    serverBundles.put(BobUserId, bundlePublicCollection);

    GroupConversation bobAliceGroupConversation2 = new GroupConversation();
    bobAliceGroupConversation2.initSender(BobDeviceId2);

    MessageExamplePayload bobSenderKeyPayload2 = new MessageExamplePayload(bobAliceGroupConversation2.getSenderKey());

    // The new device sends out its sender key to all members
    // Here we use only Alice as example
    SesameConversation bobAliceConversation2 = establishConversation(BobUserId, bobDevice2, AliceUserId);
    bobAliceConversation2.initializeSender();
    encrypted = bobAliceConversation2.encrypt(bobSenderKeyPayload2.encode());
    serverPutToMailbox(encrypted);

    // Then in some way, Bob broadcasts that there's a new device
    // so Alice and Charlie can re-send their sender key
    // we only do it for Alice in this example for simplicity
    // But first we update the conversation so the new device can be sent to
    aliceBobConversation = establishConversation(AliceUserId, aliceDevice, BobUserId);

    // Then the broadcast is received by each Alice and Charlie
    // (we only show Alice here)
    download = serverFetchEncrypted(aliceDevice.id);
    decrypted = aliceBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 2);
    aliceGroup.initRecipient(payload.contents);

    // Alice can only send to Bob after initializing secret keys
    // by either calling initializeSender or decrypting a message
    aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());
    encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // Bob2 also gets Alice latest sender key
    download = serverFetchEncrypted(bobDevice2.id);
    decrypted = bobAliceConversation2.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 2);
    bobAliceGroupConversation2.initRecipient(payload.contents);

    // THen alice sends a message to the group
    message = "Hello again".getBytes();
    encrypted = aliceGroup.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // A new Bob can read the message
    int bobAliceGroupIndex2 = bobAliceGroupIndex;
    bobAliceGroupIndex2++; // Skip the message which was sent by Bob (message BobMsg1)
    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex2++);
    decrypted = bobAliceGroupConversation2.decrypt(download);
    Assert.assertArrayEquals(decrypted, "Hello again".getBytes());

    // Old Bob also still can read the messages
    // BobMsg1
    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(download);
    Assert.assertArrayEquals(decrypted, "Hello from Bob".getBytes());

    download = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(download);
    Assert.assertArrayEquals(decrypted, "Hello again".getBytes());

  }

  /**
   * This tests a scenario where Alice has two devices and one of them
   * joins in a group
   * @throws Exception
   */
  @Test
  public void testEncryptDecryptAliceHasTwoDevices() throws Exception {
    SesameSenderDevice aliceDevice1 = initDevice(AliceDeviceId1, AliceUserId);
    SesameSenderDevice aliceDevice2 = new SesameSenderDevice(AliceDeviceId2, AliceUserId);
    byte[] bundlePublicRaw = aliceDevice2.getBundle().bundlePublic.encode();

    BundlePublicCollection bundlePublicCollection = serverBundles.get(AliceUserId);
    bundlePublicCollection.put(AliceDeviceId2, BundlePublic.decode(bundlePublicRaw));
    serverBundles.put(AliceUserId, bundlePublicCollection);

    SesameSenderDevice bobDevice = initDevice(BobDeviceId1, BobUserId);
    SesameSenderDevice charlieDevice = initDevice(CharlieDeviceId1, CharlieUserId);

    byte[] encrypted, decrypted, download;

    // ======================================== ALICE's side of story ===================================================
    HashId aliceGroupId = serverRegisterGroup();

    SesameConversation aliceBobConversation1 = establishConversation(AliceUserId, aliceDevice1, BobUserId);
    aliceBobConversation1.initializeSender();

    SesameConversation aliceCharlieConversation1 = establishConversation(AliceUserId, aliceDevice1, CharlieUserId);
    aliceCharlieConversation1.initializeSender();

    SesameConversation alice1Alice2Conversation = establishConversation(AliceUserId, aliceDevice1, AliceUserId);
    alice1Alice2Conversation.initializeSender();

    GroupConversation aliceGroup1 = new GroupConversation();
    aliceGroup1.initSender(AliceDeviceId1);
    MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup1.getSenderKey());

    // Alice sends senderKey
    encrypted = aliceBobConversation1.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = aliceCharlieConversation1.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = alice1Alice2Conversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And alice keeps the sender key for herself, so she can read whatever she sent to the group
    aliceGroup1.initRecipient(aliceSenderKeyPayload.contents);

    // That's it for setting up a group conversation.
    // Next she can send her first message to the group
    byte[] message = "Welcome".getBytes();

    encrypted = aliceGroup1.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // == Alice's second device =====================================================================================
    SesameConversation alice2Alice1Conversation = establishConversation(AliceUserId, aliceDevice2, AliceUserId);

    // This is from Alice1
    download = serverFetchEncrypted(aliceDevice2.id);
    decrypted = alice2Alice1Conversation.decrypt(download);
    MessageExamplePayload payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation aliceGroup2 = new GroupConversation();
    aliceGroup2.initSender(AliceDeviceId2);
    // Alice #2 puts Alice #1 shared key
    aliceGroup2.initRecipient(payload.contents);

    MessageExamplePayload aliceSenderKeyPayload2 = new MessageExamplePayload(aliceGroup2.getSenderKey());

    SesameConversation aliceBobConversation2 = establishConversation(AliceUserId, aliceDevice2, BobUserId);
    aliceBobConversation2.initializeSender();

    SesameConversation aliceCharlieConversation2 = establishConversation(AliceUserId, aliceDevice2, CharlieUserId);
    aliceCharlieConversation2.initializeSender();

    // Alice #2 sends senderKey
    encrypted = aliceBobConversation2.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = aliceCharlieConversation2.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);
    encrypted = alice2Alice1Conversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);


    // == BOB's story ===============================================================================================

    SesameConversation bobAliceConversation = establishConversation(BobUserId, bobDevice, AliceUserId);

    // This is sender key from Alice 1
    download = serverFetchEncrypted(bobDevice.id);
    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation bobAliceGroupConversation = new GroupConversation();
    bobAliceGroupConversation.initRecipient(payload.contents);

    // This is sender key from Alice 2
    download = serverFetchEncrypted(bobDevice.id);
    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    bobAliceGroupConversation.initRecipient(payload.contents);

    // Bob must know which messages he's not yet got from the server
    // In real life, this must not in form of integer, a message ID-like form would do
    // As long as it is kept in some records and no message is skipped
    int bobAliceGroupIndex = 0;

    byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);

    decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

    Assert.assertArrayEquals(decrypted, message);

    // Then Bob wants to reply
    // First he must generate his senderKey
    bobAliceGroupConversation.initSender(BobDeviceId1);

    MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());
    bobAliceGroupConversation.initRecipient(bobSenderKeyPayload.contents);

    // And he must send it to both Alice and Charlie.
    // He had a conversation with Alice, and he can just send it
    encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // but not with Charlie, so he must initiate conversation with Charlie
    SesameConversation bobCharlieConversation = establishConversation(BobUserId, bobDevice, CharlieUserId);
    bobCharlieConversation.initializeSender();

    // and send it to server
    encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // After that, Bob can start to send messages to the group
    // BobMsg1
    message = "Hello from Bob".getBytes();
    encrypted = bobAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice reads the message from Alice #2
    download = serverFetchEncrypted(aliceDevice1.id);
    decrypted = alice1Alice2Conversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);
    aliceGroup1.initRecipient(payload.contents);

    // And this is from Bob
    download = serverFetchEncrypted(aliceDevice1.id);
    decrypted = aliceBobConversation1.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    // Before decrypting, alice initialize the sender key from the payload
    aliceGroup1.initRecipient(payload.contents);

    int aliceAliceGroupIndex = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup1.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup1.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);

    // Before can read anything from Bob in the group,
    // Alice #2 retrieves Bob's sender key which was sent by Bob
    download = serverFetchEncrypted(aliceDevice2.id);
    decrypted = aliceBobConversation2.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    // Before decrypting, alice initialize the sender key from the payload
    aliceGroup2.initRecipient(payload.contents);

    int aliceAliceGroupIndex2 = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex2++);
    decrypted = aliceGroup2.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex2++);
    decrypted = aliceGroup2.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);

    // == Charlie's story ===============================================================================================
    SesameConversation charlieAliceConversation = establishConversation(CharlieUserId, charlieDevice, AliceUserId);
    SesameConversation charlieBobConversation = establishConversation(CharlieUserId, charlieDevice, BobUserId);

    GroupConversation charlieAliceGroupConversation = new GroupConversation();

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // Get the second private message, came from Alice 2
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // This one is from Bob
    // In real life, you should do this differently (e.g. this should happen in an event handler)
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    int charlieAliceGroupIndex = 0;
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);

  }


  SesameSenderDevice initDevice(HashId deviceId, String userId) throws NoSuchAlgorithmException, IllegalDataSizeException, InvalidKeyException, SignatureException {
    SesameSenderDevice device = new SesameSenderDevice(deviceId, userId);
    byte[] bundlePublicRaw = device.getBundle().bundlePublic.encode();
    BundlePublicCollection bundlePublicCollection = new BundlePublicCollection(deviceId, BundlePublic.decode(bundlePublicRaw));
    serverBundles.put(userId, bundlePublicCollection);
    return device;
  }

  SesameConversation establishConversation(String me, SesameSenderDevice myDevice, String target) throws IOException, IllegalDataSizeException, InvalidKeyException, SignatureException {
    BundlePublicCollection serverTargetBundlePublicCollection = serverBundles.get(target);
    byte[] download = serverTargetBundlePublicCollection.encode();
    BundlePublicCollection targetBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation targetConversation = new SesameConversation(me, myDevice.id, myDevice.getBundle(), target, targetBundlePublicCollection);

    return targetConversation;
  }
}