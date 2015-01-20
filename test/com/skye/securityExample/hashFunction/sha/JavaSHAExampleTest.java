package com.skye.securityExample.hashFunction.sha;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

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
public class JavaSHAExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Java Secure Hash Algorithm.";
		data2 = "Hello Java Secure Hash Algorithm.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * SHA-1 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA() {
		System.out.println("-- Java SHA-1 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// SHA-1 安全雜湊演算法編碼。
			encodeData = JavaSHAExample.encodeSHA(data.getBytes(charsetName));
			// SHA-1 安全雜湊演算法編碼。
			encodeData2 = JavaSHAExample.encodeSHA(data2.getBytes(charsetName));
			// 印出結果。
			print(encodeData, encodeData2);
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 校驗。
		Assert.assertArrayEquals(encodeData, encodeData2);

		System.out.println("-- Java SHA-1 End --");
		System.out.println();
	}

	/**
	 * SHA-256 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA256() {
		System.out.println("-- Java SHA-256 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// SHA-256 安全雜湊演算法編碼。
			encodeData = JavaSHAExample
					.encodeSHA256(data.getBytes(charsetName));
			// SHA-256 安全雜湊演算法編碼。
			encodeData2 = JavaSHAExample.encodeSHA256(data2
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

		System.out.println("-- Java SHA-256 End --");
		System.out.println();
	}

	/**
	 * SHA-384 安全雜湊演算法編碼。
	 * 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testEncodeSHA384() {
		System.out.println("-- Java SHA-384 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// SHA-384 安全雜湊演算法編碼。
			encodeData = JavaSHAExample
					.encodeSHA384(data.getBytes(charsetName));
			// SHA-384 安全雜湊演算法編碼。
			encodeData2 = JavaSHAExample.encodeSHA384(data2
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

		System.out.println("-- Java SHA-384 End --");
		System.out.println();
	}

	/**
	 * SHA-512 安全雜湊演算法編碼。
	 * 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testEncodeSHA512() {
		System.out.println("-- Java SHA-512 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		byte[] encodeData = null;
		byte[] encodeData2 = null;
		try {
			// SHA-512 安全雜湊演算法編碼。
			encodeData = JavaSHAExample
					.encodeSHA512(data.getBytes(charsetName));
			// SHA-512 安全雜湊演算法編碼。
			encodeData2 = JavaSHAExample.encodeSHA512(data2
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

		System.out.println("-- Java SHA-512 End --");
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
