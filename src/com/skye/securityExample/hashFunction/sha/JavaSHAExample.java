package com.skye.securityExample.hashFunction.sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Java Secure Hash Algorithm 安全雜湊演算法，SHA-1 長度為 160 byte，分為
 * SHA-1、SHA-224、SHA-256、SHA-384 及 SHA-512。
 * <p>
 * Java6 實作 SHA-1、SHA-256、SHA-384 及 SHA-512。
 * </p>
 * <p>
 * Bouncy Castle 實作 SHA-224。
 * </p>
 * 
 * @author Skye
 */
public class JavaSHAExample {
	/**
	 * SHA-1 安全雜湊演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeSHA(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA");
		return messageDigest.digest(data);
	}

	/**
	 * SHA-256 安全雜湊演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeSHA256(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		return messageDigest.digest(data);
	}

	/**
	 * SHA-384 安全雜湊演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeSHA384(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-384");
		
		return messageDigest.digest(data);
	}

	/**
	 * SHA-512 安全雜湊演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeSHA512(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
		return messageDigest.digest(data);
	}
}
