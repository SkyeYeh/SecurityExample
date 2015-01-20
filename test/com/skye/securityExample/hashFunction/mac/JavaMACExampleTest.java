package com.skye.securityExample.hashFunction.mac;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Java Message Authentication Code 訊息認證碼演算法，分為
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
public class JavaMACExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Java Message Authentication Code.";
		data2 = "Hello Java Message Authentication Code.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * HmacMD5 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacMD5() {
		System.out.println("-- Java HmacMD5 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacMD5 訊息認證碼演算法。
			key = JavaMACExample.initHmacMD5Key();
			// HmacMD5 訊息認證碼演算法。
			encodeData = JavaMACExample.encodeHmacMD5(
					data.getBytes(charsetName), key);
			// HmacMD5 訊息認證碼演算法。
			encodeData2 = JavaMACExample.encodeHmacMD5(
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

		System.out.println("-- Java HmacMD5 End --");
		System.out.println();
	}

	/**
	 * HmacSHA1 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacSHA1() {
		System.out.println("-- Java HmacSHA1 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacSHA1 訊息認證碼演算法。
			key = JavaMACExample.initHmacSHA1Key();
			// HmacSHA1 訊息認證碼演算法。
			encodeData = JavaMACExample.encodeHmacSHA1(
					data.getBytes(charsetName), key);
			// HmacSHA1 訊息認證碼演算法。
			encodeData2 = JavaMACExample.encodeHmacSHA1(
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

		System.out.println("-- Java HmacSHA1 End --");
		System.out.println();
	}

	/**
	 * HmacSHA256 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacSHA256() {
		System.out.println("-- Java HmacSHA256 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacSHA256 訊息認證碼演算法。
			key = JavaMACExample.initHmacSHA256Key();
			// HmacSHA256 訊息認證碼演算法。
			encodeData = JavaMACExample.encodeHmacSHA256(
					data.getBytes(charsetName), key);
			// HmacSHA256 訊息認證碼演算法。
			encodeData2 = JavaMACExample.encodeHmacSHA256(
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

		System.out.println("-- Java HmacSHA256 End --");
		System.out.println();
	}

	/**
	 * HmacSHA384 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacSHA384() {
		System.out.println("-- Java HmacSHA384 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacSHA384 訊息認證碼演算法。
			key = JavaMACExample.initHmacSHA384Key();
			// HmacSHA384 訊息認證碼演算法。
			encodeData = JavaMACExample.encodeHmacSHA384(
					data.getBytes(charsetName), key);
			// HmacSHA384 訊息認證碼演算法。
			encodeData2 = JavaMACExample.encodeHmacSHA384(
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

		System.out.println("-- Java HmacSHA384 End --");
		System.out.println();
	}

	/**
	 * HmacSHA512 訊息認證碼演算法。
	 */
	@Test
	public void testEncodeHmacSHA512() {
		System.out.println("-- Java HmacSHA512 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] key = null;
		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// 初始化 HmacSHA512 訊息認證碼演算法。
			key = JavaMACExample.initHmacSHA512Key();
			// HmacSHA512 訊息認證碼演算法。
			encodeData = JavaMACExample.encodeHmacSHA512(
					data.getBytes(charsetName), key);
			// HmacSHA512 訊息認證碼演算法。
			encodeData2 = JavaMACExample.encodeHmacSHA512(
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

		System.out.println("-- Java HmacSHA512 End --");
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
}
