package com.skye.securityExample.symmetricKey.des;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Bouncy Castle Data Encryption Standard 資料加密標準，密鑰長度預設為 56 byte。
 * <p>
 * Java6 密鑰長度包含 56 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至 CFB128、OFB 及 OFB8
 * 至 OFB128，填充方式包含 NoPadding、PKCS5Padding 及 ISO10126Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 64 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至
 * CFB128、OFB 及 OFB8 至 OFB128，填充方式包含
 * PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding 及
 * ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleDESExample {
	private final static String ALGORITHM = "DES";
	private final static String TRANSFORMATION = "DES/ECB/PKCS5Padding";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 生成 DES 密鑰，長度預設為 56 byte。Java6 包含 56 byte；Bouncy Castle 包含 64 byte。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initKey() throws NoSuchAlgorithmException {
		// 實體化密鑰產生器。
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);

		// 初始化 64 byte 密鑰產生器。
		keyGenerator.init(64);

		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * DES 加密。
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
		// 還原 DES 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * DES 解密。
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
		// 還原 DES 密鑰。
		Key k = toKey(key);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, k);

		return cipher.doFinal(data);
	}

	/**
	 * 還原 DES 密鑰。
	 * 
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static Key toKey(byte[] key) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException {
		// 實體化 DES 密鑰材料。
		KeySpec keySpec = new DESKeySpec(key);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance(ALGORITHM);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

		return secretKey;
	}
}
