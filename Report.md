# Report

1. **Forward Security**:
   - Output keys from the past appear random to an adversary who learns the KDF key at some point in time.
   - Forward security ensures that if an attacker compromises a party’s keys at a specific point in time, they cannot retroactively decrypt earlier messages.
   - The Double Ratchet achieves forward security by using a KDF (Key Derivation Function) chain. Each message generates new keys, and earlier keys cannot be calculated from later ones.
2. **Break-in Recovery**:
   - Future output keys appear random to an adversary who learns the KDF key at some point in time, provided that future inputs have added sufficient entropy.
   - Break-in recovery refers to the ability to recover from a compromise of a party’s keys.
   - The symmetric-key ratchet uses constant inputs for sending and receiving chains, so they don't provide break-in recovery. Therefore, DH outputs are used as KDF inputs to a root chain, and the KDF outputs from the root chain are used as sending and receiving chain keys. Using a KDF chain here improves resilience and break-in recovery.
3. **Not Updating DH Keys**:
   - If parties never update their Diffie-Hellman (DH) keys, forward secrecy and break-in recovery are compromised.
   - Forward secrecy: Without key updates, an attacker who learns the KDF key can calculate all previous keys, violating forward secrecy.
   - Break-in recovery: Similarly, without key updates, new output keys won’t appear random to an attacker who knows the KDF key, undermining break-in recovery.
4. **Longest Sending Chain**:
   - When the sender changes in the dialogue, i.e. Alice just sent a few messages but now receives a message from Bob. , her sending chain will be reset by generating a new ratchet key pair, combining the new private key with the newly received public key of Bob to get the DH output,  and feeding the DH output to the root KDF to calculate a new root key (RK) and sending chain key (CK). 
   - Therefore, the longest sending chain occurs when Alice/Bob sends the maximum messages in a row. For Alice, 2 messages -> 3 CKs or 2 symmetric-key ratchet steps in total. For Bob, 1 message -> 2 CKs or 1 symmetric-key ratchet steps in total.
   
   ![image-20240627222405960](C:\Users\Athena\AppData\Roaming\Typora\typora-user-images\image-20240627222405960.png)
   
   - The picture above shows the state of Alice's sending chain.
5. **Security Property for Mallory’s Compromise**:
   - The relevant security property is **future secrecy**.
   - [Even though Mallory compromised Alice’s phone and stole her keys, she cannot determine the locker combination because the Double Ratchet ensures that later keys cannot be calculated from earlier ones](https://crypto.stackexchange.com/questions/60111/questions-about-the-double-ratchet-mechanism-in-signal)[2](https://crypto.stackexchange.com/questions/60111/questions-about-the-double-ratchet-mechanism-in-signal).