package com.skye.securityExample.digitalSignature.rsaSign;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.skye.securityExample.digitalSignature.rsaSign.JavaRSASignExample;

/**
 * Java RSA Sign 典型數位簽章演算法，私鑰簽章公鑰驗章，基於大數因數分解。
 * <p>
 * Java6 密鑰長度預設為 1024 byte，包含 512 至 65536(64 的倍數) byte，演算法包含
 * MD2withRSA、MD5withRSA 及 SHA1withRSA。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度預設為 2048 byte，包含 512 至 65536(64 的倍數) byte，演算法包含
 * SHA224withRSA、SHA256withRSA、SHA384withRSA、SHA512withRSA 、RIPEMD128withRSA 及
 * RIPEMD160withRSA。
 * </p>
 * 
 * @author Skye
 */
public class JavaRSASignExampleTest {
	private String data = null;
	private byte[] publicKey = null;
	private byte[] privateKey = null;

	@Before
	public void setUp() throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		System.out.println("-- JAVA RSA Sign Start --");

		data = "Hello Java RSA Sign.";
		Map<String, Key> keyMap = JavaRSASignExample.initKey();
		publicKey = JavaRSASignExample.getPublicKey(keyMap);
		privateKey = JavaRSASignExample.getPrivateKey(keyMap);

		System.out.println("Data\t：" + data);
		System.out.println("PublicKey\t："
				+ Base64.encodeBase64String(publicKey));
		System.out.println("PrivateKey\t："
				+ Base64.encodeBase64String(privateKey));
	}

	@After
	public void tearDown() {
		data = null;
		System.out.println("-- JAVA RSA Sign End --");
		System.out.println();
	}

	/**
	 * RSA 使用私鑰簽章。RSA 使用公鑰驗章。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testSign() {
		byte[] sign = null;
		boolean verify = false;

		try {
			sign = JavaRSASignExample.sign(data.getBytes(), privateKey);
			System.out.println("Sign\t：" + Base64.encodeBase64String(sign));

			verify = JavaRSASignExample
					.verify(data.getBytes(), publicKey, sign);
			System.out.println("Verify\t：" + verify);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertTrue(verify);
	}
}
