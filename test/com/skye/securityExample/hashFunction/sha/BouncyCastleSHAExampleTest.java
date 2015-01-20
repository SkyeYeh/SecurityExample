package com.skye.securityExample.hashFunction.sha;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Bouncy Castle Secure Hash Algorithm 安全雜湊演算法，SHA-1 長度為 160 byte，分為
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
public class BouncyCastleSHAExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Bouncy Castle Secure Hash Algorithm.";
		data2 = "Hello Bouncy Castle Secure Hash Algorithm.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * SHA-224 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA224() {
		System.out.println("-- Bouncy Castle SHA-224 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// SHA-224 安全雜湊演算法編碼。
			encodeData = BouncyCastleSHAExample.encodeSHA224(data
					.getBytes(charsetName));
			// SHA-224 安全雜湊演算法編碼。
			encodeData2 = BouncyCastleSHAExample.encodeSHA224(data2
					.getBytes(charsetName));
			// 印出結果。
			print(encodeData, encodeData2);
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 校驗。
		Assert.assertArrayEquals(encodeData, encodeData2);

		System.out.println("-- Bouncy Castle SHA-224 End --");
		System.out.println();
	}

	/**
	 * SHA-224 安全雜湊演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeSHA224Hex() {
		System.out.println("-- Bouncy Castle SHA-224 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// SHA-224 安全雜湊演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleSHAExample.encodeSHA224Hex(data
					.getBytes(charsetName));
			// SHA-224 安全雜湊演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleSHAExample.encodeSHA224Hex(data2
					.getBytes(charsetName));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Bouncy Castle SHA-224 Hex End --");
		System.out.println();
	}

	/**
	 * 印出結果。
	 * 
	 * @param encodeData
	 * @param encodeData2
	 * @throws UnsupportedEncodingException
	 */
	private static void print(byte[] encodeData, byte[] encodeData2)
			throws UnsupportedEncodingException {
		System.out.println("EncodeData\t："
				+ new String(encodeData, charsetName));
		System.out.println("EncodeData2\t："
				+ new String(encodeData2, charsetName));
	}

	/**
	 * 印出結果。
	 * 
	 * @param encodeData
	 * @param encodeData2
	 */
	private static void print(String encodeData, String encodeData2) {
		System.out.println("EncodeData\t：" + encodeData);
		System.out.println("EncodeData2\t：" + encodeData2);
	}
}
