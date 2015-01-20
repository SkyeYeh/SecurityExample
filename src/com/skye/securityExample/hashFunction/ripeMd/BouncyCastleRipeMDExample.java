package com.skye.securityExample.hashFunction.ripeMd;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Bouncy Castle RACE Integrity primitives Evaluation Message Digest
 * 訊息摘要演算法，RipeMD128 長度為 128 byte，分為 RipeMD128、RipeMD160、RipeMD256 及 RipeMD320
 * 四種。僅 Bouncy Castle 實作。
 * 
 * @author Skye
 */
public class BouncyCastleRipeMDExample {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * RipeMD128 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeRipeMD128(byte[] data)
			throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("RipeMD128");
		return messageDigest.digest(data);
	}

	/**
	 * RipeMD128 訊息摘要演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeRipeMD128Hex(byte[] data)
			throws NoSuchAlgorithmException {
		byte[] encodeData = encodeRipeMD128(data);
		return new String(Hex.encode(encodeData));
	}

	/**
	 * RipeMD160 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeRipeMD160(byte[] data)
			throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("RipeMD160");
		return messageDigest.digest(data);
	}

	/**
	 * RipeMD160 訊息摘要演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeRipeMD160Hex(byte[] data)
			throws NoSuchAlgorithmException {
		byte[] encodeData = encodeRipeMD160(data);
		return new String(Hex.encode(encodeData));
	}

	/**
	 * RipeMD256 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeRipeMD256(byte[] data)
			throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("RipeMD256");
		return messageDigest.digest(data);
	}

	/**
	 * RipeMD256 訊息摘要演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeRipeMD256Hex(byte[] data)
			throws NoSuchAlgorithmException {
		byte[] encodeData = encodeRipeMD256(data);
		return new String(Hex.encode(encodeData));
	}

	/**
	 * RipeMD320 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeRipeMD320(byte[] data)
			throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("RipeMD320");
		return messageDigest.digest(data);
	}

	/**
	 * RipeMD320 訊息摘要演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeRipeMD320Hex(byte[] data)
			throws NoSuchAlgorithmException {
		byte[] encodeData = encodeRipeMD320(data);
		return new String(Hex.encode(encodeData));
	}
}
