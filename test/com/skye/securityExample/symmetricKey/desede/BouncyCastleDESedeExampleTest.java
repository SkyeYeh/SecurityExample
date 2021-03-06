package com.skye.securityExample.symmetricKey.desede;

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
 * Bouncy Castle Triple Data Encryption Standard 三重資料加密標準，密鑰長度預設為 168 byte。
 * <p>
 * Java6 密鑰長度包含 112 及 168 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至 CFB128、OFB
 * 及 OFB8 至 OFB128，填充方式包含 NoPadding、PKCS5Padding 及 ISO10126Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 128 及 192 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至
 * CFB128、OFB 及 OFB8 至 OFB128，填充方式包含
 * PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding 及
 * ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleDESedeExampleTest {
	private String data = null;

	@Before
	public void setUp() {
		data = "Hello Bouncy Castle Triple Data Encryption Standard.";
	}

	@After
	public void tearDown() {
		data = null;
	}

	/**
	 * DESede 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncrypt() {
		System.out.println("-- JAVA DESede Start --");
		System.out.println("Data\t：" + data);

		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			byte[] key = BouncyCastleDESedeExample.initKey();
			System.out.println("Key\t：" + Base64.encodeBase64String(key));

			encodeData = BouncyCastleDESedeExample
					.encrypt(data.getBytes(), key);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = BouncyCastleDESedeExample.decrypt(encodeData, key);
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

		System.out.println("-- JAVA DESede End --");
		System.out.println();
	}
}
