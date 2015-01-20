package com.skye.securityExample.hashFunction.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Bouncy Castle Message Authentication Code 訊息認證碼演算法，分為
 * HmacMD2、HmacMD4、HmacMD5、HmacSHA1、HmacSHA224、HmacSHA256、HmacSHA384 及
 * HmacSHA512。
 * <p>
 * Java6 實作 HmacMD5、HmacSHA1、HmacSHA256、HmacSHA384 及 HmacSHA512。
 * </p>
 * <p>
 * Bouncy Castle 實作 HmacMD2、HmacMD4 及 HmacSHA224。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleMACExample {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 初始化 HmacMD2 訊息認證碼演算法。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initHmacMD2Key() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD2");
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * HmacMD2 訊息認證碼演算法。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] encodeHmacMD2(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD2");
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		return mac.doFinal(data);
	}

	/**
	 * HmacMD2 訊息認證碼演算法，回傳 16 進位字串。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static String encodeHmacMD2Hex(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] encodeData = encodeHmacMD2(data, key);
		return new String(Hex.encode(encodeData));
	}

	/**
	 * 初始化 HmacMD4 訊息認證碼演算法。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initHmacMD4Key() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD4");
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * HmacMD4 訊息認證碼演算法。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] encodeHmacMD4(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD4");
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		return mac.doFinal(data);
	}

	/**
	 * HmacMD4 訊息認證碼演算法，回傳 16 進位字串。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static String encodeHmacMD4Hex(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] encodeData = encodeHmacMD4(data, key);
		return new String(Hex.encode(encodeData));
	}

	/**
	 * 初始化 HmacSHA224 訊息認證碼演算法。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] initHmacSHA224Key() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA224");
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * HmacSHA224 訊息認證碼演算法。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] encodeHmacSHA224(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA224");
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		return mac.doFinal(data);
	}

	/**
	 * SHA224 訊息認證碼演算法，回傳 16 進位字串。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static String encodeHmacSHA224Hex(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] encodeData = encodeHmacSHA224(data, key);
		return new String(Hex.encode(encodeData));
	}
}
