package com.skye.securityExample.digitalSignature.ecdsaSign;

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

/**
 * Java ECDSA Sign 橢圓曲線數位簽章演算法，私鑰簽章公鑰驗章，微軟序號驗證演算法。
 * <p>
 * Bouncy Castle 密鑰長度無限制，演算法包含 NONEwithECDSA
 * 、RIPEMD160withECDSA、SHA1withECDSA、SHA224withECDSA、SHA256withECDSA
 * 、SHA384withECDSA 及 SHA512withECDSA。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleECDSASignExampleTest {
	private String data = null;
	private byte[] publicKey = null;
	private byte[] privateKey = null;

	@Before
	public void setUp() throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		System.out.println("-- Bouncy Castle ECDSA Sign Start --");

		data = "Hello Java ECDSA Sign.";
		Map<String, Key> keyMap = BouncyCastleECDSASignExample.initKey();
		publicKey = BouncyCastleECDSASignExample.getPublicKey(keyMap);
		privateKey = BouncyCastleECDSASignExample.getPrivateKey(keyMap);

		System.out.println("Data\t：" + data);
		System.out.println("PublicKey\t："
				+ Base64.encodeBase64String(publicKey));
		System.out.println("PrivateKey\t："
				+ Base64.encodeBase64String(privateKey));
	}

	@After
	public void tearDown() {
		data = null;
		System.out.println("-- Bouncy Castle ECDSA Sign End --");
		System.out.println();
	}

	/**
	 * ECDSA 使用私鑰簽章。ECDSA 使用公鑰驗章。
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
			sign = BouncyCastleECDSASignExample.sign(data.getBytes(),
					privateKey);
			System.out.println("Sign\t：" + Base64.encodeBase64String(sign));

			verify = BouncyCastleECDSASignExample.verify(data.getBytes(),
					publicKey, sign);
			System.out.println("Verify\t：" + verify);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertTrue(verify);
	}
}
