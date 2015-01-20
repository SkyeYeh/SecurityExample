package com.skye.securityExample.symmetricKey.aes;

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
 * Java Advanced Encryption Standard 高階加密標準，密鑰長度預設為 128 byte。
 * <p>
 * Java6 密鑰長度包含 128、192 及 256(需 JCE) byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8 至
 * CFB128、OFB 及 OFB8 至 OFB128，填充方式包含 NoPadding、PKCS5Padding 及 ISO10126Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 128、192 及 256 byte，工作模式包含 ECB、CBC、PCBC、CTR、CTS、CFB、CFB8
 * 至 CFB128、OFB 及 OFB8 至 OFB128，填充方式包含
 * PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding 及
 * ZeroBytePadding。此範例也可使用 DES、DESede、RC2、RC4 及 Blowfish 演算法。
 * </p>
 * 
 * @author Skye
 */
public class JavaAESExampleTest {
	private String data = null;

	@Before
	public void setUp() {
		data = "Hello Java Advanced Encryption Standard.";
	}

	@After
	public void tearDown() {
		data = null;
	}

	/**
	 * AES 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncrypt() {
		System.out.println("-- JAVA AES Start --");
		System.out.println("Data\t：" + data);

		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			byte[] key = JavaAESExample.initKey();
			System.out.println("Key\t：" + Base64.encodeBase64String(key));

			encodeData = JavaAESExample.encrypt(data.getBytes(), key);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = JavaAESExample.decrypt(encodeData, key);
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

		System.out.println("-- JAVA AES End --");
		System.out.println();
	}
}
