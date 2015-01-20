package com.skye.securityExample.web;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.skye.securityExample.digitalSignature.rsaSign.JavaRSASignExample;
import com.skye.securityExample.publicKey.rsa.JavaRSAExample;
import com.skye.securityExample.symmetricKey.aes.JavaAESExample;

/**
 * 使用 RSA 公鑰加密 AES 金鑰， 傳送給 Server 接收回傳的資料，使用 AES 解密取得簽章值及內文，簽章值長度與 AES
 * 金鑰長度相同(預設為 128 byte)，並使用 RSA 公鑰驗章。
 * 
 * @author Skye
 */
public class DataServletTest {
	private static final String URL = "http://127.0.0.1:8080/SecurityExample/dataServlet";
	private static final String BASE64_RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCacUbKLGoMInxuPjsaPAgASkTipKbPpiBoTsIp+QUtwd7FcftAxAwXZrx/j58CNeFlvBLrQn3GC78+5T+m8w50fG94EC+C0xBRQ+XzFeBZ/jUl8iQOHcrr74YfR88U/Y09iJMlDFca9oSRLHeIA09F2hi03i1GwVs0m15jcEXPVwIDAQAB";
	private static final int AES_KEY_LENGTH = 128;

	private byte[] rsaPublicKey;
	private byte[] aesKey;

	@Before
	public final void setUp() {
		rsaPublicKey = Base64.decodeBase64(BASE64_RSA_PUBLIC_KEY);

		try {
			aesKey = JavaAESExample.initKey();
		} catch (NoSuchAlgorithmException e) {
			Assert.fail();
		}
	}

	@Test
	public final void test() {
		// RSA 使用公鑰加密。
		byte[] rsaAesKey = null;
		try {
			rsaAesKey = JavaRSAExample.encryptByPublicKey(aesKey, rsaPublicKey);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail();
		}

		// 連線。
		byte[] inputData = null;
		try {
			inputData = conn(rsaAesKey);
		} catch (IOException e) {
			e.printStackTrace();
			Assert.fail();
		}

		// AES 解密。
		byte[] byteData = null;
		try {
			byteData = JavaAESExample.decrypt(inputData, aesKey);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail();
		}

		// 取得簽章值。
		byte[] sign = null;
		try {
			sign = getSign(byteData);
		} catch (DecoderException e) {
			e.printStackTrace();
			Assert.fail();
		}

		// 取得資料。
		String data = getData(byteData);

		// 驗證。
		try {
			Assert.assertTrue(JavaRSASignExample.verify(data.getBytes(),
					rsaPublicKey, sign));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail();
		}
	}

	/**
	 * 取得簽章值。
	 * 
	 * @param byteData
	 * @return
	 * @throws DecoderException
	 */
	private byte[] getSign(byte[] byteData) throws DecoderException {
		String data = new String(byteData);
		String hexSign = data.substring(0, AES_KEY_LENGTH * 2);
		return Hex.decodeHex(hexSign.toCharArray());
	}

	/**
	 * 取得資料。
	 * 
	 * @param byteData
	 * @return
	 */
	private String getData(byte[] byteData) {
		String data = new String(byteData);
		return data.substring(AES_KEY_LENGTH * 2);
	}

	/**
	 * 連線。
	 * 
	 * @param rsaAesKey
	 * @return
	 * @throws IOException
	 */
	private byte[] conn(byte[] outputData) throws IOException {
		byte[] respData = null;
		URL url = new URL(URL);
		HttpURLConnection conn = null;
		try {
			// 初始化連線。
			conn = initConn(url);

			// 寫入封包中。
			setOutputData(outputData, conn);

			// 讀取輸入。
			respData = getInputData(conn);
		} catch (IOException e) {
			throw e;
		} finally {
			if (conn != null) {
				conn.disconnect();
				conn = null;
			}
		}
		return respData;
	}

	/**
	 * 將資料寫入封包中。
	 * 
	 * @param data
	 * @param conn
	 * @throws IOException
	 */
	private void setOutputData(byte[] data, HttpURLConnection conn)
			throws IOException {
		DataOutputStream dataOutputStream = new DataOutputStream(
				conn.getOutputStream());
		if (data != null) {
			dataOutputStream.write(data);
		}
		dataOutputStream.flush();
		dataOutputStream.close();
	}

	/**
	 * 初始化連線。
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 * @throws ProtocolException
	 */
	private HttpURLConnection initConn(URL url) throws IOException,
			ProtocolException {
		HttpURLConnection conn;
		conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setDoInput(true);
		return conn;
	}

	/**
	 * 讀取輸入。
	 * 
	 * @param conn
	 * @return
	 * @throws IOException
	 */
	private static byte[] getInputData(HttpURLConnection conn)
			throws IOException {
		int contentLength = conn.getContentLength();
		byte[] result = null;
		if (contentLength > 0) {
			result = new byte[contentLength];
			InputStream in = conn.getInputStream();
			DataInputStream dataInputStream = new DataInputStream(in);
			dataInputStream.readFully(result);
			in.close();
			dataInputStream.close();
		}
		return result;
	}
}
