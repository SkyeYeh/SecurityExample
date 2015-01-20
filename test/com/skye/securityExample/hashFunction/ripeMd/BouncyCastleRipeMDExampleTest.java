package com.skye.securityExample.hashFunction.ripeMd;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.skye.securityExample.hashFunction.ripeMd.BouncyCastleRipeMDExample;

/**
 * Bouncy Castle RACE Integrity primitives Evaluation Message Digest
 * 訊息摘要演算法，RipeMD128 長度為 128 byte，分為 RipeMD128、RipeMD160、RipeMD256 及 RipeMD320
 * 四種。僅 Bouncy Castle 實作。
 * 
 * @author Skye
 */
public class BouncyCastleRipeMDExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Bouncy Castle RACE Integrity primitives Evaluation Message Digest.";
		data2 = "Hello Bouncy Castle RACE Integrity primitives Evaluation Message Digest.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * RipeMD128 訊息摘要演算法編碼。
	 */
	@Test
	public void testEncodeRipeMD128() {
		System.out.println("-- Bouncy Castle RipeMD128 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// RipeMD128 訊息摘要演算法編碼。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD128(data
					.getBytes(charsetName));
			// RipeMD128 訊息摘要演算法編碼。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD128(data2
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

		System.out.println("-- Bouncy Castle RipeMD128 End --");
		System.out.println();
	}

	/**
	 * RipeMD128 訊息摘要演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeRipeMD128Hex() {
		System.out.println("-- Bouncy Castle RipeMD128 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// RipeMD128 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD128Hex(data
					.getBytes(charsetName));
			// RipeMD128 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD128Hex(data2
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

		System.out.println("-- Bouncy Castle RipeMD128 Hex End --");
		System.out.println();
	}

	/**
	 * RipeMD160 訊息摘要演算法編碼。
	 */
	@Test
	public void testEncodeRipeMD160() {
		System.out.println("-- Bouncy Castle RipeMD160 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// RipeMD160 訊息摘要演算法編碼。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD160(data
					.getBytes(charsetName));
			// RipeMD160 訊息摘要演算法編碼。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD160(data2
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

		System.out.println("-- Bouncy Castle RipeMD160 End --");
		System.out.println();
	}

	/**
	 * RipeMD160 訊息摘要演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeRipeMD160Hex() {
		System.out.println("-- Bouncy Castle RipeMD160 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// RipeMD160 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD160Hex(data
					.getBytes(charsetName));
			// RipeMD160 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD160Hex(data2
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

		System.out.println("-- Bouncy Castle RipeMD160 Hex End --");
		System.out.println();
	}

	/**
	 * RipeMD256 訊息摘要演算法編碼。
	 */
	@Test
	public void testEncodeRipeMD256() {
		System.out.println("-- Bouncy Castle RipeMD256 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// RipeMD256 訊息摘要演算法編碼。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD256(data
					.getBytes(charsetName));
			// RipeMD256 訊息摘要演算法編碼。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD256(data2
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

		System.out.println("-- Bouncy Castle RipeMD256 End --");
		System.out.println();
	}

	/**
	 * RipeMD256 訊息摘要演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeRipeMD256Hex() {
		System.out.println("-- Bouncy Castle RipeMD256 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// RipeMD256 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD256Hex(data
					.getBytes(charsetName));
			// RipeMD256 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD256Hex(data2
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

		System.out.println("-- Bouncy Castle RipeMD256 Hex End --");
		System.out.println();
	}

	/**
	 * RipeMD320 訊息摘要演算法編碼。
	 */
	@Test
	public void testEncodeRipeMD320() {
		System.out.println("-- Bouncy Castle RipeMD320 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// RipeMD320 訊息摘要演算法編碼。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD320(data
					.getBytes(charsetName));
			// RipeMD320 訊息摘要演算法編碼。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD320(data2
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

		System.out.println("-- Bouncy Castle RipeMD320 End --");
		System.out.println();
	}

	/**
	 * RipeMD320 訊息摘要演算法編碼，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeRipeMD320Hex() {
		System.out.println("-- Bouncy Castle RipeMD320 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// RipeMD320 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData = BouncyCastleRipeMDExample.encodeRipeMD320Hex(data
					.getBytes(charsetName));
			// RipeMD320 訊息摘要演算法編碼，回傳 16 進位字串。
			encodeData2 = BouncyCastleRipeMDExample.encodeRipeMD320Hex(data2
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

		System.out.println("-- Bouncy Castle RipeMD320 Hex End --");
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
