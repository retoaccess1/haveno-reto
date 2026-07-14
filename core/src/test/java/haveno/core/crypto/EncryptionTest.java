/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package haveno.core.crypto;

import haveno.common.crypto.CryptoException;
import haveno.common.crypto.Encryption;
import haveno.common.crypto.KeyRing;
import haveno.common.crypto.KeyStorage;
import haveno.common.file.FileUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionTest {
    private KeyRing keyRing;
    private File dir;

    @BeforeEach
    public void setup() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, CryptoException {
        dir = File.createTempFile("temp_tests", "");
        dir.delete();
        dir.mkdir();
        KeyStorage keyStorage = new KeyStorage(dir);
        keyRing = new KeyRing(keyStorage, null, true);
    }

    @AfterEach
    public void tearDown() throws IOException {
        FileUtil.deleteDirectory(dir);
    }

    // -----------------------------------------------------------------------
    // AES/CBC round-trip
    // -----------------------------------------------------------------------

    @Test
    public void testEncryptDecryptRoundTrip() throws CryptoException {
        SecretKey key = Encryption.generateSecretKey(128);
        byte[] plaintext = "Hello Haveno!".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = Encryption.encrypt(plaintext, key);
        byte[] decrypted = Encryption.decrypt(encrypted, key);

        assertArrayEquals(plaintext, decrypted, "Decrypted bytes must match original plaintext");
    }

    @Test
    public void testEncryptProducesDifferentCiphertextsForSamePlaintext() throws CryptoException {
        SecretKey key = Encryption.generateSecretKey(128);
        byte[] plaintext = "same plaintext".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted1 = Encryption.encrypt(plaintext, key);
        byte[] encrypted2 = Encryption.encrypt(plaintext, key);

        // With a random IV each call must produce a different ciphertext
        assertFalse(java.util.Arrays.equals(encrypted1, encrypted2),
                "Two encryptions of the same plaintext must produce different ciphertexts (CBC with random IV)");
    }

    @Test
    public void testEncryptedOutputIsLargerThanPlaintext() throws CryptoException {
        SecretKey key = Encryption.generateSecretKey(128);
        byte[] plaintext = "test".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = Encryption.encrypt(plaintext, key);

        // Output must be at least IV (16 bytes) + 1 block (16 bytes)
        assertTrue(encrypted.length >= 32,
                "Encrypted output must include a 16-byte IV prefix");
    }

    // -----------------------------------------------------------------------
    // encryptPayloadWithHmac / decryptPayloadWithHmac round-trip
    // -----------------------------------------------------------------------

    @Test
    public void testEncryptDecryptPayloadWithHmacRoundTrip() throws CryptoException {
        SecretKey key = Encryption.generateSecretKey(256);
        byte[] payload = "Sensitive trade data".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = Encryption.encryptPayloadWithHmac(payload, key);
        byte[] decrypted = Encryption.decryptPayloadWithHmac(encrypted, key);

        assertArrayEquals(payload, decrypted, "Payload must survive encrypt/decrypt with HMAC intact");
    }

    @Test
    public void testTamperedCiphertextFailsHmacVerification() throws CryptoException {
        SecretKey key = Encryption.generateSecretKey(256);
        byte[] payload = "Important data".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = Encryption.encryptPayloadWithHmac(payload, key);
        // Flip a byte in the middle of the ciphertext
        encrypted[encrypted.length / 2] ^= 0xFF;

        assertThrows(CryptoException.class, () -> Encryption.decryptPayloadWithHmac(encrypted, key),
                "Tampered ciphertext must not decrypt successfully");
    }

    // -----------------------------------------------------------------------
    // Backward compatibility: legacy AES/ECB data must still decrypt
    // -----------------------------------------------------------------------

    @Test
    public void testLegacyEcbEncryptedDataStillDecrypts() throws Exception {
        SecretKey key = Encryption.generateSecretKey(128);
        byte[] plaintext = "Legacy ECB data".getBytes(StandardCharsets.UTF_8);

        // Encrypt directly with the old AES/ECB cipher (simulating pre-fix persisted data)
        Cipher ecbCipher = Cipher.getInstance("AES");
        ecbCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] legacyEncrypted = ecbCipher.doFinal(plaintext);

        // The new decrypt() must still recover the plaintext via its fallback path
        byte[] decrypted = Encryption.decrypt(legacyEncrypted, key);
        assertArrayEquals(plaintext, decrypted,
                "Legacy AES/ECB ciphertext must still be decryptable via the backward-compat fallback");
    }
}
