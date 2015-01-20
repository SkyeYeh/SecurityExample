package com.skye.securityExample.symmetricKey.desede;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * Java Triple Data Encryption Standard 三重資料加密標準，密鑰長度預設為 168 byte。
 * <p>
 * Java6 密鑰長度包含 112 及 168 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至 CFB128、OFB
 * 及 OFB8 至 OFB128，填充方式包含 NoPadding、PKCS5Padding 及 ISO10126Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 128 及 192 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至
 * CFB128、OFB 及 OFB8 至 OFB128，填充方式包含
 * PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding 及
 * ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class JavaDESedeExample {
	private final static String ALGORITHM = "DESede";
	private final static String TRANSFORMATION = "DESede/ECB/PKCS5Padding";

	/**
	 * 生成 DESede 密鑰，長度預設為 168 byte。Java6 包含 112 及 168 byte；Bouncy Castle 包含 128
	 * 及 192 byte。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initKey() throws NoSuchAlgorithmException {
		// 實體化密鑰產生器。
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);

		// 初始化密鑰產生器，預設長度為 168 byte。
		// keyGenerator.init(168);

		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * DESede 加密。
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
		// 還原 DESede 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * DESede 解密。
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
		// 還原 DESede 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * 還原 DESede 密鑰。
	 * 
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static Key toKey(byte[] key) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException {
		// 實體化 DESede 密鑰材料。
		KeySpec keySpec = new DESedeKeySpec(key);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance(ALGORITHM);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

		return secretKey;
	}
}
