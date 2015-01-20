package com.skye.securityExample.symmetricKey.idea;

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
 * Bouncy Castle IDEA 國際資料加密標準，密鑰長度預設為 128 byte。
 * <p>
 * Bouncy Castle 密鑰長度包含 128 byte，工作模式包含 ECB，填充方式包含
 * PKCS5Padding、PKCS7Padding、ISO10126Padding 及 ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleIDEAExample {
	private final static String ALGORITHM = "IDEA";
	private final static String TRANSFORMATION = "IDEA/ECB/PKCS5Padding";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 生成 IDEA 密鑰，長度預設為 128 byte。Java6 包含 128、192 及 256(需 JCE) byte；Bouncy
	 * Castle 包含 128、192 及 256 byte。
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
	 * IDEA 加密。
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
		// 還原 IDEA 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * IDEA 解密。
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
		// 還原 IDEA 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * 還原 IDEA 密鑰。
	 * 
	 * @param key
	 * @return
	 */
	private static Key toKey(byte[] key) {
		// 實體化 IDEA 密鑰材料。
		SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

		return secretKey;
	}
}
