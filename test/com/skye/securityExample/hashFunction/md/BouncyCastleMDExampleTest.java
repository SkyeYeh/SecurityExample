package com.skye.securityExample.hashFunction.md;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Bouncy Castle Message Digest 訊息摘要演算法，長度為 128 byte，分為 MD2、MD4 及 MD5 三種。
 * <p>
 * Java6 實作 MD2 及 MD5。
 * </p>
 * <p>
 * Bouncy Castle 實作 MD4。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleMDExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Bouncy Castle Message Digest.";
		data2 = "Hello Bouncy Castle Message Digest.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * MD4 訊息摘要演算法編碼。
	 */
	@Test
	public void testEncodeMD4() {
		System.out.println("-- Bouncy Castle MD4 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// MD4 訊息摘要演算法編碼。
			encodeData = BouncyCastleMDExample.encodeMD4(data
					.getBytes(charsetName));
			// MD4 訊息摘要演算法編碼。
			encodeData2 = BouncyCastleMDExample.encodeMD4(data2
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

		System.out.println("-- Bouncy Castle MD4 End --");
		System.out.println();
	}

	/**
	 * MD4 訊息摘要演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeMD4Hex() {
		System.out.println("-- Bouncy Castle MD4 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// MD4 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleMDExample.encodeMD4Hex(data
					.getBytes(charsetName));
			// MD4 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleMDExample.encodeMD4Hex(data2
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

		System.out.println("-- Bouncy Castle MD4 Hex End --");
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
