package com.skye.securityExample.symmetricKey.pbe;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Java PBE 密碼基礎加密。
 * <p>
 * Java6 密鑰長度包含 PBEWithMD5AndDES(56 byte)、PBEWithMD5AndTripleDES(168 及 112
 * byte)、PBEWithSHA1AndDESede(168 及 112 byte) 及 PBEWithSHA1AndRC2_40(128 及 40 至
 * 1024 byte)，工作模式包含 CBC，填充方式包含 PKCS5Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 PBEWithMD5AndDES(64 byte)、 PBEWithMD5AndRC2(128 byte)、
 * PBEWithSHA1AndDES(64 byte)、 PBEWithSHA1AndRC2(128 byte)、
 * PBEWithSHAAndIDEA-CBC(128 byte)、 PBEWithSHAAnd2-KeyTripleDES-CBC(128 byte)、
 * PBEWithSHAAnd3-KeyTripleDES-CBC(128 byte)、 PBEWithSHAAnd128BitRC2-CBC(128
 * byte)、 PBEWithSHAAnd40BitRC2-CBC(40 byte)、 PBEWithSHAAnd128BitRC4(128 byte)、
 * PBEWithSHAAnd40BitRC4(40 byte) 及 PBEWithSHAAndTwofish-CBC(256 byte)，工作模式包含
 * CBC，填充方式包含 PKCS5Padding、PKCS7Padding、ISO10126Padding 及 ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class JavaPBEExample {
	private final static String ALGORITHM = "PBEWithMD5AndDES";
	private static final int ITERATION_COUNT = 100;

	/**
	 * 生成 PBE 鹽，長度為 8 byte。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initSalt() throws NoSuchAlgorithmException {
		// 實體化安全亂數。
		SecureRandom random = new SecureRandom();

		return random.generateSeed(8);
	}

	/**
	 * PBE 加密。
	 * 
	 * @param data
	 * @param pwd
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] data, String pwd, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// 還原 PBE 密鑰。
		Key k = toKey(pwd);
		PBEParameterSpec spec = new PBEParameterSpec(salt, ITERATION_COUNT);

		Cipher cipher = Cipher.getInstance(ALGORITHM);

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, k, spec);

		return cipher.doFinal(data);
	}

	/**
	 * PBE 解密。
	 * 
	 * @param data
	 * @param pwd
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(byte[] data, String pwd, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		Key k = toKey(pwd);
		PBEParameterSpec spec = new PBEParameterSpec(salt, ITERATION_COUNT);

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, k, spec);

		return cipher.doFinal(data);
	}

	/**
	 * 還原 PBE 密鑰。
	 * 
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static Key toKey(String pwd) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		// 實體化 PBE 密鑰材料。
		KeySpec keySpec = new PBEKeySpec(pwd.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance(ALGORITHM);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

		return secretKey;
	}
}
