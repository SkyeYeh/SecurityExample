package com.skye.securityExample.symmetricKey.aes;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Bouncy Castle Advanced Encryption Standard 高階加密標準，密鑰長度預設為 128 byte。
 * <p>
 * Java6 密鑰長度包含 128、192 及 256(需 JCE) byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至
 * CFB128、OFB 及 OFB8 至 OFB128，填充方式包含 NoPadding、PKCS5Padding 及 ISO10126Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 128、192 及 256 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8
 * 至 CFB128、OFB 及 OFB8 至 OFB128，填充方式包含
 * PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding 及
 * ZeroBytePadding。此範例也可使用 DES、DESede、RC2、RC4 及 Blowfish 演算法。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleAESExample {
	private final static String ALGORITHM = "AES";
	private final static String TRANSFORMATION = "AES/ECB/PKCS5Padding";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 生成 AES 密鑰，長度預設為 128 byte。Java6 包含 128、192 及 256(需 JCE) byte；Bouncy Castle
	 * 包含 128、192 及 256 byte。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initKey() throws NoSuchAlgorithmException {
		// 實體化密鑰產生器。
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);

		// 初始化 128 byte 密鑰產生器。
		keyGenerator.init(128);

		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * AES 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] data, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		// 還原 AES 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * AES 解密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(byte[] data, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		// 還原 AES 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * 還原 AES 密鑰。
	 * 
	 * @param key
	 * @return
	 */
	private static Key toKey(byte[] key) {
		// 實體化 AES 密鑰材料。
		SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

		return secretKey;
	}
}
