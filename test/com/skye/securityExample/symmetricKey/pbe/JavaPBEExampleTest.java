package com.skye.securityExample.symmetricKey.pbe;

import java.security.InvalidAlgorithmParameterException;
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
 * Java PBE 密碼基礎加密。
 * <p>
 * Java6 密鑰長度包含 PBEWithMD5AndDES(56 byte)、PBEWithMD5AndTripleDES(168 及 112
 * byte)、PBEWithSHA1AndDESede(168 及 112 byte) 及 PBEWithSHA1AndRC2_40(128 及 40 至
 * 1024 byte)，工作模式包含 CBC，填充方式包含 PKCS5Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度包含 PBEWithMD5AndDES(64 byte)、 PBEWithMD5AndRC2(128 byte)、
 * PBEWithSHA1AndDES(64 byte)、 PBEWithSHA1AndRC2(128 byte)、
 * PBEWithSHAAndIDEA-CBC(128 byte)、 PBEWithSHAAnd2-KeyTripleDES-CBC(128 byte)、
 * PBEWithSHAAnd3-KeyTripleDES-CBC(128 byte)、 PBEWithSHAAnd128BitRC2-CBC(128
 * byte)、 PBEWithSHAAnd40BitRC2-CBC(40 byte)、 PBEWithSHAAnd128BitRC4(128 byte)、
 * PBEWithSHAAnd40BitRC4(40 byte) 及 PBEWithSHAAndTwofish-CBC(256 byte)，工作模式包含
 * CBC，填充方式包含 PKCS5Padding、PKCS7Padding、ISO10126Padding 及 ZeroBytePadding。
 * </p>
 * 
 * @author Skye
 */
public class JavaPBEExampleTest {
	private String data = null;
	private String pwd = null;

	@Before
	public void setUp() {
		data = "Hello Java PBE.";
		pwd = "!QAZ2wsx.";
	}

	@After
	public void tearDown() {
		data = null;
		pwd = null;
	}

	/**
	 * PBE 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncrypt() {
		System.out.println("-- JAVA PBE Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Password\t：" + pwd);

		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			byte[] salt = JavaPBEExample.initSalt();
			System.out.println("Salt\t：" + Base64.encodeBase64String(salt));

			encodeData = JavaPBEExample.encrypt(data.getBytes(), pwd, salt);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = JavaPBEExample.decrypt(encodeData, pwd, salt);
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
		} catch (InvalidAlgorithmParameterException e) {
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertEquals(data, new String(decodeData));

		System.out.println("-- JAVA PBE End --");
		System.out.println();
	}
}
