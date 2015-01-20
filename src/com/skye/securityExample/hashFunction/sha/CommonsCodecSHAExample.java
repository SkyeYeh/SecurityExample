package com.skye.securityExample.hashFunction.sha;

import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * Commons Codec Secure Hash Algorithm 安全雜湊演算法，SHA-1 長度為 160 byte，分為
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
public class CommonsCodecSHAExample {
	/**
	 * SHA-1 安全雜湊演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeSHA(byte[] data) throws NoSuchAlgorithmException {
		return DigestUtils.sha1Hex(data);
	}

	/**
	 * SHA-256 安全雜湊演算法編碼。
	 * 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeSHA256(byte[] data)
			throws NoSuchAlgorithmException {
		return DigestUtils.sha256Hex(data);
	}

	/**
	 * SHA-384 安全雜湊演算法編碼。
	 * 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeSHA384(byte[] data)
			throws NoSuchAlgorithmException {
		return DigestUtils.sha384Hex(data);
	}

	/**
	 * SHA-512 安全雜湊演算法編碼。
	 * 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeSHA512(byte[] data)
			throws NoSuchAlgorithmException {
		return DigestUtils.sha512Hex(data);
	}
}
