package com.skye.securityExample.hashFunction.mac;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

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
public class BouncyCastleMACExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void serUp() {
		data = "Hello Bouncy Castle Message Authentication Code.";
		data2 = "Hello Bouncy Castle Message Authentication Code.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * HmacMD2 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacMD2() {
		System.out.println("-- Bouncy Castle HmacMD2 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacMD2 訊息認證碼演算法。
			key = BouncyCastleMACExample.initHmacMD2Key();
			// HmacMD2 訊息認證碼演算法。
			encodeData = BouncyCastleMACExample.encodeHmacMD2(
					data.getBytes(charsetName), key);
			// HmacMD2 訊息認證碼演算法。
			encodeData2 = BouncyCastleMACExample.encodeHmacMD2(
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

		System.out.println("-- Bouncy Castle HmacMD2 End --");
		System.out.println();
	}

	/**
	 * HmacMD2 訊息認證碼演算法，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeHmacMD2Hex() {
		System.out.println("-- Bouncy Castle HmacMD2 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		String encodeData = null;
		String encodeData2 = null;
		try {
			// 初始化 HmacMD2 訊息認證碼演算法，回傳 16 進位字串。
			key = BouncyCastleMACExample.initHmacMD2Key();
			// HmacMD2 訊息認證碼演算法，回傳 16 進位字串。
			encodeData = BouncyCastleMACExample.encodeHmacMD2Hex(
					data.getBytes(charsetName), key);
			// HmacMD2 訊息認證碼演算法，回傳 16 進位字串。
			encodeData2 = BouncyCastleMACExample.encodeHmacMD2Hex(
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

		System.out.println("-- Bouncy Castle HmacMD2 Hex End --");
		System.out.println();
	}

	/**
	 * HmacMD4 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacMD4() {
		System.out.println("-- Bouncy Castle HmacMD4 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacMD4 訊息認證碼演算法。
			key = BouncyCastleMACExample.initHmacMD4Key();
			// HmacMD4 訊息認證碼演算法。
			encodeData = BouncyCastleMACExample.encodeHmacMD4(
					data.getBytes(charsetName), key);
			// HmacMD4 訊息認證碼演算法。
			encodeData2 = BouncyCastleMACExample.encodeHmacMD4(
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

		System.out.println("-- Bouncy Castle HmacMD4 End --");
		System.out.println();
	}

	/**
	 * HmacMD4 訊息認證碼演算法，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeHmacMD4Hex() {
		System.out.println("-- Bouncy Castle HmacMD4 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		String encodeData = null;
		String encodeData2 = null;
		try {
			// 初始化 HmacMD4 訊息認證碼演算法。
			key = BouncyCastleMACExample.initHmacMD4Key();
			// HmacMD4 訊息認證碼演算法，回傳 16 進位字串。
			encodeData = BouncyCastleMACExample.encodeHmacMD4Hex(
					data.getBytes(charsetName), key);
			// HmacMD4 訊息認證碼演算法，回傳 16 進位字串。
			encodeData2 = BouncyCastleMACExample.encodeHmacMD4Hex(
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

		System.out.println("-- Bouncy Castle HmacMD4 Hex End --");
		System.out.println();
	}

	/**
	 * HmacSHA224 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacSHA224() {
		System.out.println("-- Bouncy Castle HmacSHA224 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacSHA224 訊息認證碼演算法。
			key = BouncyCastleMACExample.initHmacSHA224Key();
			// HmacSHA224 訊息認證碼演算法。
			encodeData = BouncyCastleMACExample.encodeHmacSHA224(
					data.getBytes(charsetName), key);
			// HmacSHA224 訊息認證碼演算法。
			encodeData2 = BouncyCastleMACExample.encodeHmacSHA224(
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

		System.out.println("-- Bouncy Castle HmacSHA224 End --");
		System.out.println();
	}

	/**
	 * SHA224 訊息認證碼演算法，回傳 16 進位字串。
	 */
	@Test
	public void testEncodeHmacSHA224Hex() {
		System.out.println("-- Bouncy Castle HmacSHA224 Hex Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		String encodeData = null;
		String encodeData2 = null;
		try {
			// 初始化 HmacSHA224 訊息認證碼演算法。
			key = BouncyCastleMACExample.initHmacSHA224Key();
			// HmacSHA224 訊息認證碼演算法，回傳 16 進位字串。
			encodeData = BouncyCastleMACExample.encodeHmacSHA224Hex(
					data.getBytes(charsetName), key);
			// HmacSHA224 訊息認證碼演算法，回傳 16 進位字串。
			encodeData2 = BouncyCastleMACExample.encodeHmacSHA224Hex(
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

		System.out.println("-- Bouncy Castle HmacSHA224 Hex End --");
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
