package com.skye.securityExample.symmetricKey.idea;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Bouncy Castle IDEA 國際資料加密標準，密鑰長度預設為 128 byte。
 * <p>
 * Bouncy Castle 密鑰長度包含 128 byte，工作模式包含 ECB，填充方式包含
 * PKCS5Padding、PKCS7Padding、ISO10126Padding 及 ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleIDEAExampleTest {
	private String data = null;

	@Before
	public void setUp() {
		data = "Hello Bouncy Castle IDEA.";
	}

	@After
	public void tearDown() {
		data = null;
	}

	/**
	 * IDEA 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncrypt() {
		System.out.println("-- JAVA IDEA Start --");
		System.out.println("Data\t：" + data);

		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			byte[] key = BouncyCastleIDEAExample.initKey();
			System.out.println("Key\t：" + Base64.encodeBase64String(key));

			encodeData = BouncyCastleIDEAExample.encrypt(data.getBytes(), key);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = BouncyCastleIDEAExample.decrypt(encodeData, key);
			System.out.println("DecodeData\t：" + new String(decodeData));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (InvalidKeyException e) {
			Assert.fail(e.toString());
		} catch (InvalidKeySpecException e) {
			Assert.fail(e.toString());
		} catch (NoSuchPaddingException e) {
			Assert.fail(e.toString());
		} catch (IllegalBlockSizeException e) {
			Assert.fail(e.toString());
		} catch (BadPaddingException e) {
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertEquals(data, new String(decodeData));

		System.out.println("-- JAVA IDEA End --");
		System.out.println();
	}
}
