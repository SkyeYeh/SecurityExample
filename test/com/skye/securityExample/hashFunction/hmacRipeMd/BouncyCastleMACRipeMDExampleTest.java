package com.skye.securityExample.hashFunction.hmacRipeMd;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.skye.securityExample.hashFunction.hmacRipeMd.BouncyCastleMACRipeMDExample;

/**
 * Bouncy Castle Message Authentication Code RACE Integrity primitives
 * Evaluation Message Digest 訊息摘要演算法，HmacRipeMD128 長度為 128 byte，分為 HmacRipeMD128
 * 及 RipeMD160 兩種。僅 Bouncy Castle 實作。
 * 
 * @author Skye
 */
public class BouncyCastleMACRipeMDExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Bouncy Castle Message Authentication Code RACE Integrity primitives Evaluation Message Digest.";
		data2 = "Hello Bouncy Castle Message Authentication Code RACE Integrity primitives Evaluation Message Digest.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * HmacRipeMD128 訊息認證碼演算法編碼。
	 */
	@Test
	public void testEncodeHmacRipeMD128() {
		System.out.println("-- Bouncy Castle HmacRipeMD128 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacRipeMD128 訊息認證碼演算法。
			key = BouncyCastleMACRipeMDExample.iniHmacRipeMD128Key();
			// HmacRipeMD128 訊息認證碼演算法編碼。
			encodeData = BouncyCastleMACRipeMDExample.encodeHmacRipeMD128(
					data.getBytes(charsetName), key);
			// HmacRipeMD128 訊息認證碼演算法編碼。
			encodeData2 = BouncyCastleMACRipeMDExample.encodeHmacRipeMD128(
					data2.getBytes(charsetName), key);
			// 印出結果。
			print(encodeData, encodeData2);
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		} catch (InvalidKeyException e) {
			Assert.fail(e.toString());
		}
		// 校驗。
		Assert.assertArrayEquals(encodeData, encodeData2);

		System.out.println("-- Bouncy Castle HmacRipeMD128 End --");
		System.out.println();
	}

	/**
	 * HmacRipeMD128 訊息認證碼演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeRipeMD128Hex() {
		System.out.println("-- Bouncy Castle HmacRipeMD128 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		String encodeData = null;
		String encodeData2 = null;
		try {
			// 初始化 HmacRipeMD128 訊息認證碼演算法。
			key = BouncyCastleMACRipeMDExample.iniHmacRipeMD128Key();
			// HmacRipeMD128 訊息認證碼演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleMACRipeMDExample.encodeHmacRipeMD128Hex(
					data.getBytes(charsetName), key);
			// HmacRipeMD128 訊息認證碼演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleMACRipeMDExample.encodeHmacRipeMD128Hex(
					data2.getBytes(charsetName), key);
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		} catch (InvalidKeyException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Bouncy Castle HmacRipeMD128 Hex End --");
		System.out.println();
	}
	
	/**
	 * HmacRipeMD160 訊息認證碼演算法編碼。
	 */
	@Test
	public void testEncodeHmacRipeMD160() {
		System.out.println("-- Bouncy Castle HmacRipeMD160 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacRipeMD160 訊息認證碼演算法。
			key = BouncyCastleMACRipeMDExample.iniHmacRipeMD160Key();
			// HmacRipeMD160 訊息認證碼演算法編碼。
			encodeData = BouncyCastleMACRipeMDExample.encodeHmacRipeMD160(
					data.getBytes(charsetName), key);
			// HmacRipeMD160 訊息認證碼演算法編碼。
			encodeData2 = BouncyCastleMACRipeMDExample.encodeHmacRipeMD160(
					data2.getBytes(charsetName), key);
			// 印出結果。
			print(encodeData, encodeData2);
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		} catch (InvalidKeyException e) {
			Assert.fail(e.toString());
		}
		// 校驗。
		Assert.assertArrayEquals(encodeData, encodeData2);

		System.out.println("-- Bouncy Castle HmacRipeMD160 End --");
		System.out.println();
	}

	/**
	 * HmacRipeMD160 訊息認證碼演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeRipeMD160Hex() {
		System.out.println("-- Bouncy Castle HmacRipeMD160 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		String encodeData = null;
		String encodeData2 = null;
		try {
			// 初始化 HmacRipeMD160 訊息認證碼演算法。
			key = BouncyCastleMACRipeMDExample.iniHmacRipeMD160Key();
			// HmacRipeMD160 訊息認證碼演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleMACRipeMDExample.encodeHmacRipeMD160Hex(
					data.getBytes(charsetName), key);
			// HmacRipeMD160 訊息認證碼演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleMACRipeMDExample.encodeHmacRipeMD160Hex(
					data2.getBytes(charsetName), key);
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		} catch (InvalidKeyException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Bouncy Castle HmacRipeMD160 Hex End --");
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
