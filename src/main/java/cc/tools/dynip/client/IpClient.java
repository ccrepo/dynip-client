
package cc.tools.dynip.client;

import java.io.*;

import java.lang.reflect.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;

import javax.crypto.Cipher;

/**
 * This class implements a client for the dynip-server process. This program
 * demonstrates asymmetric key usage.
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public final class IpClient {

	/**
	 * Main method.
	 * 
	 * @param args program arguments.
	 */
	public static void main(String[] args) {
		System.out.println(new Date() + ": running");

		if (IpConfig.ipConfig().isHelp(args)) {
			IpConfig.ipConfig().doHelp();
			return;
		}

		if (!IpConfig.ipConfig().loadParameters(args) || !IpConfig.ipConfig().isValid()) {

			System.err.println("error: invalid parameters " + IpConfig.ipConfig().getErrors().size() + " errors");
			for (String error : IpConfig.ipConfig().getErrors()) {
				System.err.println("error: " + error);
			}
			return;
		}

		IpConfig.ipConfig().doDump();

		IpClient ipClient = new IpClient();

		if (!ipClient.isValid()) {
			System.err.println("error: client failed to initialise");
			return;
		}

		if (!ipClient.updateServer()) {
			System.err.println("error: server call failed");
			return;
		}

		System.out.println("fini.");
	}

	/**
	 * Constructor {@link IpClient}.
	 */
	public IpClient() {

		try {
			_keyFactory = KeyFactory.getInstance(IpConfig.CONSTANT_KEY_ALGORITHM_RSA);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("exception: IpClient " + e.getClass().getName() + ": " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		}

		if (_keyFactory == null) {
			System.err.println("error: KeyFactory init failed");
			return;
		}

		File credentialsFile = new File(IpConfig.ipConfig().getCredentials());

		if (!credentialsFile.exists() || !credentialsFile.canRead()) {
			System.err.println("error: public key at '" + credentialsFile + "' not accessible");
			return;
		}

		if (!initCredentials(IpConfig.ipConfig().getCredentials())) {
			return;
		}

		if (!IpConfig.ipConfig().getClientPublicKey().isBlank()
				&& !IpConfig.ipConfig().getClientPrivateKey().isBlank()) {

			File clientPrivateKeyFile = new File(IpConfig.ipConfig().getClientPrivateKey());

			if (!clientPrivateKeyFile.exists() || !clientPrivateKeyFile.canRead()) {
				System.err.println("error: private key at '" + clientPrivateKeyFile + "' not accessible");
				return;
			}

			File clientPublicKeyFile = new File(IpConfig.ipConfig().getClientPublicKey());

			if (!clientPublicKeyFile.exists() || !clientPublicKeyFile.canRead()) {
				System.err.println("error: public key at '" + clientPublicKeyFile + "' not accessible");
				return;
			}

			if (!initClientPrivateKeyFromFile(IpConfig.ipConfig().getClientPrivateKey())
					| !initClientPublicKeyFromFile(IpConfig.ipConfig().getClientPublicKey())) {
				return;
			}
		} else {
			if (!initClientPublicAndPrivateKeys()) {
				return;
			}
		}

		if (!IpConfig.ipConfig().getServerPublicKey().isBlank()) {

			File serverPublicKeyFile = new File(IpConfig.ipConfig().getServerPublicKey());

			if (!serverPublicKeyFile.exists() || !serverPublicKeyFile.canRead()) {
				System.err.println("error: public key at '" + serverPublicKeyFile + "' not accessible");
				return;
			}

			if (!initServerPublicKeyFromFile(IpConfig.ipConfig().getServerPublicKey())) {
				return;
			}

		} else {
			if (!initServerPublicKeyFromServer()) {
				return;
			}
		}
		
		_isValid = true;
	}

	/**
	 * Method returns boolean indicating whether {@link IpConfig} object is in a
	 * valid state.
	 * 
	 * @return boolean where true indicates {@link IpConfig} object is valid, false
	 *         otherwise.
	 */
	public boolean isValid() {
		return _isValid;
	}

	/**
	 * Method contacts server to update server's IP address list.
	 * 
	 * @return boolean true if update succeeded, false otherwise.
	 */
	public boolean updateServer() {

		StringBuilder ip = new StringBuilder();

		if (!getPublicIpFromServer(ip)) {
			System.err.println("error: getPublicIpFromServer failed");
			return false;
		}

		if (!setPublicIpOnServer(ip.toString())) {
			System.err.println("error: setPublicOnFromServer failed");
			return false;
		}

		return true;
	}

	/**
	 * Method to build outgoing message data
	 * 
	 * @param data     {@link java.util.Map} to return results.
	 * @param random1  random value for unique message header identifier.
	 * @param publicIp public ip address of this client. ignored if parameter is
	 *                 null or empty.
	 * @return boolean to indicate success with true, false otherwise.
	 */
	private boolean buildServerMessageData(Map<String, String> data, String random1, String publicIp) {
		data.put(IpConfig.CONSTANT_HTTP_KEY_HEADER, encryptData(_serverPublicKey, random1));

		if (publicIp != null && !publicIp.isBlank()) {
			data.put(IpConfig.CONSTANT_HTTP_KEY_PUBLIC_IP, encryptData(_serverPublicKey, publicIp));
		}

		data.put(IpConfig.CONSTANT_HTTP_KEY_USER, encryptData(_serverPublicKey, _user));
		data.put(IpConfig.CONSTANT_HTTP_KEY_PASSWORD, encryptData(_serverPublicKey, _password));

		for (Map.Entry<String, String> clientPublicKeySubstring : _clientPublicKeySubstrings.entrySet()) {
			data.put(clientPublicKeySubstring.getKey(),
					encryptData(_serverPublicKey, clientPublicKeySubstring.getValue()));
		}

		data.put(IpConfig.CONSTANT_HTTP_KEY_TOTAL,
				encryptData(_serverPublicKey, Integer.toString(_clientPublicKeySubstrings.size())));

		return true;
	}

	/**
	 * Method {@link java.util.Base64} decodes data and returns name/value pairs in
	 * {@link java.util.Map}. Values are the result of decoding parameter
	 * base64EncodedData.
	 * 
	 * @param base64EncodedData {@link java.util.Base64} encoded name/value pairs.
	 * @return {@link java.util.Map} containing decoded name/value pairs.
	 */
	private Map<String, String> decodeData(String base64EncodedData) {
		Map<String, String> data = new HashMap<String, String>();
		String[] assignments = base64EncodedData.split("&");
		for (String assignment : assignments) {
			String[] tuple = assignment.split("=");
			if (tuple.length == 1) {
				data.put(tuple[0], "");
			} else if (tuple.length == 2) {
				data.put(tuple[0], URLDecoder.decode(tuple[1], StandardCharsets.UTF_8));
			} else {
				System.out.println("skipped '" + assignment + "'");
			}
		}
		return data;
	}

	/**
	 * Method performs data decryption and returns plain-text using
	 * {@link java.security.PrivateKey} parameter {@link java.security.PrivateKey}.
	 * 
	 * @param encryptedData encrypted {@link java.util.Base64} text to be decrypted.
	 * @param privateKey    {@link java.security.PrivateKey} to be used to decrypt.
	 * @return String containing plain text result of decryption if success, else
	 *         null.
	 */
	private String decryptData(String encryptedData, PrivateKey privateKey) {

		if (encryptedData == null || encryptedData.isBlank()) {
			System.err.println("error: no data in deceypt data");
			return null;
		}

		try {
			final Cipher cipher = Cipher.getInstance(IpConfig.CONSTANT_CYPHER_TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
		} catch (Exception e) {
			System.err.println("exception: decryptData " + e.getClass().getName() + " - " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		}

		return null;
	}

	/**
	 * Method performs http get call to server and returns status of a http get call
	 * and server response data in responseBuffer parameter
	 * 
	 * @param url            server url to call.
	 * @param responseBuffer buffer to return server response to caller.
	 * @throws Exception based on errors encountered formatting/encoding data and
	 *                   communicating with server.
	 * @return int containing returned http status.
	 *         {@link java.net.HttpURLConnection} (HTTP_OK
	 *         {@value java.net.HttpURLConnection#HTTP_OK}, HTTP_BAD_REQUEST
	 *         {@value java.net.HttpURLConnection#HTTP_BAD_REQUEST} etc). server
	 *         response is returned in parameter responseBuffer
	 */
	private int doGet(String url, StringBuilder responseBuffer) throws Exception {
		StringBuilder result = new StringBuilder();
		HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
		conn.setRequestMethod("GET");
		int code = conn.getResponseCode();
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
			for (String line; (line = reader.readLine()) != null;) {
				result.append(line);
			}
		}
		responseBuffer.append(result.toString());
		return code;
	}

	/**
	 * Method performs http put call to server and returns status of a http put call
	 * and server response data in responseBuffer parameter.
	 * 
	 * @param url            server url to call.
	 * @param responseBuffer buffer to return server response to caller.
	 * @param data           name/value pairs of data that should be sent to server.
	 * @throws Exception based on errors encountered formatting/encoding data and.
	 *                   communicating with server.
	 * @return int containing returned http status.
	 *         {@link java.net.HttpURLConnection} (HTTP_OK
	 *         {@value java.net.HttpURLConnection#HTTP_OK}, HTTP_BAD_REQUEST
	 *         {@value java.net.HttpURLConnection#HTTP_BAD_REQUEST} etc). server
	 *         response is returned in parameter responseBuffer
	 */
	private int doPost(String url, StringBuilder responseBuffer, Map<String, String> data) throws Exception {
		HttpRequest request = HttpRequest.newBuilder().POST(encodeData(data)).uri(URI.create(url))
				.setHeader("User-Agent", this.getClass().getSimpleName() + "command line program")
				.header("Content-Type", "application/x-www-form-urlencoded").build();

		HttpResponse<String> httpResponse = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		responseBuffer.append(httpResponse.body());
		return httpResponse.statusCode();
	}

	/**
	 * Method performs data encryption and returns {@link java.util.Base64} encoded
	 * cypher text of string contained in PlainText parameter using the target
	 * server's {@link java.security.PublicKey}.
	 * {@link initServerPublicKeyFromFile(String)} or
	 * {@link initServerPublicKeyFromServer()} must be called before this method.
	 * 
	 * @param publicKey {@link java.security.PublicKey} to be used to encrypt
	 * @param plainText plain text to be encrypted.
	 * @return String containing {@link java.util.Base64} encoded text result of
	 *         encryption if success, else null.
	 */
	private String encryptData(PublicKey publicKey, String plainText) {

		if (plainText == null || plainText.isBlank()) {
			System.err.println("error: no data in encrypt data");
			return null;
		}

		if (_serverPublicKey == null) {
			System.err.println("error: encryptData server PublicKey is null - call Setter for server Key first.");
			return null;
		}

		try {
			Cipher cipher = Cipher.getInstance(IpConfig.CONSTANT_CYPHER_TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
		} catch (Exception e) {
			System.err.println("exception: encryptData " + e.getClass().getName() + " - " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		}

		return null;
	}

	/**
	 * Method Url encodes data.
	 * 
	 * @param data name value pairs in Map to be encoded by method.
	 * @return {@link HttpRequest.BodyPublisher} of encoded String data.
	 */
	private HttpRequest.BodyPublisher encodeData(Map<String, String> data) {
		StringBuilder buffer = new StringBuilder();
		for (Map.Entry<String, String> entry : data.entrySet()) {
			buffer.append(!buffer.isEmpty() ? "&" : "");
			buffer.append(URLEncoder.encode(entry.getKey().toString(), StandardCharsets.UTF_8));
			buffer.append("=");
			buffer.append(URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8));
		}
		return HttpRequest.BodyPublishers.ofString(buffer.toString());
	}

	/**
	 * Method loads {@link java.security.Key} from file based on parameter values.
	 * 
	 * @param filename       location of file which contains
	 *                       {@link java.security.Key}.
	 * @param keySpecClass   class indicating the type of the
	 *                       {@link java.security.Key} that should be created.
	 * @param pattern        value in header and footer of {@link java.security.Key}
	 *                       file that need to be removed.
	 * @param generateMethod method name for generation of {@link java.security.Key}
	 *                       object.
	 * @return created {@link java.security.Key} value if success, else null.
	 */
	private Key getKey(String filename, Class<?> keySpecClass, String pattern, String generateMethod) {
		StringBuilder buffer = new StringBuilder();

		if (!loadFile(filename, buffer)) {
			System.err.println("error: unable to load file " + filename);
			return null;
		}

		return getKeyFromString(buffer.toString(), keySpecClass, pattern, generateMethod);
	}

	/**
	 * Method loads {@link java.security.Key} from file based on parameter values.
	 * 
	 * @param base64EncodedString {@link java.security.Key} encoded as base 64
	 *                            string.
	 * 
	 * @param keySpecClass        class indicating the type of the
	 *                            {@link java.security.Key} that should be created.
	 * @param pattern             value in header and footer of
	 *                            {@link java.security.Key} file that need to be
	 *                            removed.
	 * @param generateMethod      method name for generation of
	 *                            {@link java.security.Key} object.
	 * @return created {@link java.security.Key} value if success, else null.
	 */
	private Key getKeyFromString(String base64EncodedString, Class<?> keySpecClass, String pattern,
			String generateMethod) {

		byte[] decoded = Base64.getDecoder()
				.decode(base64EncodedString.replaceAll("\\n", "").replaceAll("-----BEGIN " + pattern + " KEY-----", "")
						.replaceAll("-----END " + pattern + " KEY-----", "").trim());

		try {
			Constructor<?> constructor = keySpecClass.getDeclaredConstructor(decoded.getClass());
			Object object = constructor.newInstance(new Object[] { decoded });
			if (object instanceof KeySpec) {
				KeySpec keySpec = (KeySpec) object;
				Method method = _keyFactory.getClass().getDeclaredMethod(generateMethod, KeySpec.class);
				object = method.invoke(_keyFactory, keySpec);
				if (object instanceof Key) {
					return (Key) object;
				}
			}
		} catch (Exception e) {
			System.err.println("exception: getKey " + e.getClass().getName() + " - " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * Method reads and returns {@link java.security.PrivateKey} value from file.
	 * 
	 * @param privateKeyFilename location of file containing
	 *                           {@link java.security.PrivateKey}.
	 * @return {@link java.security.PrivateKey} object extracted from
	 *         privateKeyFilename if success, else null.
	 */
	private PrivateKey getPrivateKeyFromFile(String privateKeyFilename) {
		Key privateKey = getKey(privateKeyFilename, PKCS8EncodedKeySpec.class, "PRIVATE", "generatePrivate");

		if (privateKey instanceof PrivateKey) {
			return (PrivateKey) privateKey;
		}

		StringBuilder buffer = new StringBuilder();
		buffer.append("error: could not load private key from ");
		buffer.append(privateKeyFilename);
		System.err.println(buffer.toString());
		return null;
	}

	/**
	 * Method updates the server's allowed IP address list. It sends the server a
	 * random header which the server bounces back. The received value is checked
	 * against the sent value. In addition the client's public ip address (as seen
	 * by the server) is returned to this client.
	 * 
	 * @param ipOut the returned public ip address from the server is returned to
	 *              method caller in this parameter.
	 * @return boolean value set to true for success, false otherwise.
	 */
	private boolean getPublicIpFromServer(StringBuilder ipOut) {

		try {
			StringBuilder responseBuffer = new StringBuilder();
			Map<String, String> requestData = new HashMap<String, String>();
			String random = getRandom();

			if (!buildServerMessageData(requestData, random, "")) {
				System.err.println("error: unable to build message data");
				return false;
			}

			int code = doPost(IpConfig.ipConfig().getGetUrl(), responseBuffer, requestData);
			if (code != HttpURLConnection.HTTP_OK) {
				System.err.println("error: call to server get ip failed - code " + Integer.toString(code));
				return false;
			}

			Map<String, String> responseData = decodeData(responseBuffer.toString());

			String ipResponse = decryptData(responseData.get(IpConfig.CONSTANT_HTTP_KEY_PUBLIC_IP), _clientPrivateKey);

			boolean result = true;

			if (!isEqualNotNull(random,
					decryptData(responseData.get(IpConfig.CONSTANT_HTTP_KEY_HEADER), _clientPrivateKey))) {
				System.err.println("error: mismatch '" + IpConfig.CONSTANT_HTTP_KEY_HEADER + "' bounced from server");
				result = false;
			}

			if (!isValidInet4Address(ipResponse)) {
				System.err
						.println("error: mismatch '" + IpConfig.CONSTANT_HTTP_KEY_PUBLIC_IP + "' bounced from server");
				result = false;
			}

			if (!result) {
				return false;
			}

			if (!ipOut.isEmpty()) {
				System.err.println("error: out parameter is not empty - found '" + ipOut + "'");
				return false;
			}

			ipOut.append(ipResponse);

		} catch (Exception e) {
			System.err.println("exception: getPublicIpFromServer " + e.getClass().getName() + ": " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
			return false;
		}

		return true;
	}

	/**
	 * Method gets the server's public key encoded as a base64 string. It then uses
	 * this to set property {@link #_serverPublicKey}.
	 * 
	 * @return boolean value set to true for success, false otherwise.
	 */
	private boolean getPublicKeyFromServer() {

		StringBuilder responseBuffer = new StringBuilder();

		try {
			int code = doGet(IpConfig.ipConfig().getCertificateUrl(), responseBuffer);
			if (code != HttpURLConnection.HTTP_OK) {
				System.err.println("error: call to get certificate failed - code " + Integer.toString(code));
				return false;
			}
		} catch (Exception e) {
			System.err.println("exception: get certificate " + e.getClass().getName() + ": " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
			return false;
		}

		Key publicKey = getKeyFromString(responseBuffer.toString(), X509EncodedKeySpec.class, "PUBLIC",
				"generatePublic");

		if (publicKey == null || !(publicKey instanceof PublicKey)) {
			return false;
		}

		_serverPublicKey = (PublicKey) publicKey;

		return true;
	}

	/**
	 * Method reads and returns {@link java.security.PublicKey} value from file.
	 * 
	 * @param publicKeyFilename location of file containing
	 *                          {@link java.security.PublicKey}.
	 * @return {@link java.security.PublicKey} object extracted from (@param
	 *         publicKeyFilename) if success, else null.
	 */
	private PublicKey getPublicKeyFromFile(String publicKeyFilename) {
		Key publicKey = getKey(publicKeyFilename, X509EncodedKeySpec.class, "PUBLIC", "generatePublic");

		if (publicKey instanceof PublicKey) {
			return (PublicKey) publicKey;
		}

		StringBuilder buffer = new StringBuilder();
		buffer.append("error: could not load public key from ");
		buffer.append(publicKeyFilename);
		System.err.println(buffer.toString());
		return null;
	}

	/**
	 * Method generates and returns random value. It uses {@link Math#random()} and
	 * {@link java.time.Instant#toEpochMilli}.
	 * 
	 * @return String containing random value.
	 */
	private String getRandom() {
		StringBuilder buffer = new StringBuilder();
		buffer.append(Long.toString(Instant.now().toEpochMilli()));
		buffer.append("_");
		buffer.append(Double.toString(Math.random()));
		return buffer.toString();
	}

	/**
	 * Method sets client {@link java.security.PrivateKey} value by reading it from
	 * file.
	 * 
	 * @param clientPrivateKeyFilename location of file containing
	 *                                 {@link java.security.PrivateKey}.
	 * @return boolean indicating success or failure.
	 */
	private boolean initClientPrivateKeyFromFile(String clientPrivateKeyFilename) {
		_clientPrivateKey = getPrivateKeyFromFile(clientPrivateKeyFilename);
		return _clientPrivateKey != null;
	}

	/**
	 * Method sets client {@link java.security.PublicKey} object by reading it from
	 * file.
	 * 
	 * @param clientPublicKeyFilename location of file containing
	 *                                {@link java.security.PublicKey}.
	 * @return boolean indicating success or failure.
	 */
	private boolean initClientPublicKeyFromFile(String clientPublicKeyFilename) {
		_clientPublicKey = getPublicKeyFromFile(clientPublicKeyFilename);

		if (_clientPublicKey == null) {
			System.err.println("error: client public key could not be extracted from file " + clientPublicKeyFilename);
			return false;
		}
		
		if (!initClientPublicKeyStrings()) {
			return false;
		}
		
		return true;
	}
	
	/**
	 * Method splits the base64 representation of the client {@link java.security.PublicKey} 
	 * and stores the {@link java.util.Base64} encoded string in {@link _clientPublicKeySubstrings }.
	 * @return boolean indicating success or failure.
	 */
	private boolean initClientPublicKeyStrings() {
		
		String algorithm = _clientPublicKey.getAlgorithm();
		if (algorithm == null || IpConfig.CONSTANT_KEY_ALGORITHM_RSA.compareTo(algorithm) != 0) {
			System.err.println("error: key algorithm invalid");
			return false;
		}

		String format = _clientPublicKey.getFormat();
		if (format == null) {
			System.err.println("error: key format invalid");
			return false;
		}

		byte[] bytes = _clientPublicKey.getEncoded();
		if (bytes == null || bytes.length == 0) {
			System.err.println("error: key bytes is empty");
			return false;
		}

		String clientPublicKeyString = Base64.getEncoder().encodeToString(bytes);
		if (clientPublicKeyString == null || clientPublicKeyString.isBlank()) {
			System.err.println("error: " + algorithm + " key to data conversion failed");
			return false;
		}

		int i = 0;
		for (int j = 0; i < clientPublicKeyString
				.length(); i += IpConfig.CONSTANT_MAXIMUM_RSA_ENCODE_BUFFER_LENGTH, j++) {
			String clientPublicKeySubstring = clientPublicKeyString.substring(i,
					Math.min(i + IpConfig.CONSTANT_MAXIMUM_RSA_ENCODE_BUFFER_LENGTH, clientPublicKeyString.length()));
			_clientPublicKeySubstrings.put(IpConfig.CONSTANT_HTTP_KEY_PART_N + j, clientPublicKeySubstring);
		}

		return true;
	}

	/**
	 * Method creates both the client public and private keys.
	 * 
	 * @return true if successful, false otherwise.
	 */
	private boolean initClientPublicAndPrivateKeys() {

		StringBuilder buffer1 = new StringBuilder();
		StringBuilder buffer2 = new StringBuilder();

		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(IpConfig.CONSTANT_KEY_ALGORITHM_RSA);
			kpg.initialize(IpConfig.CONSTANT_KEY_ALGORITHM_RSA_KEY_LENGTH);
			KeyPair kp = kpg.generateKeyPair();

			_clientPrivateKey = kp.getPrivate();
			_clientPublicKey = kp.getPublic();
			
			if (!initClientPublicKeyStrings()) {
				return false;
			}

			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	/**
	 * Method sets client's server credentials using pre-encryped value from file.
	 * 
	 * @param credentialsFilename location of file containing credentials.
	 * @return boolean indicating success or failure.
	 */
	private boolean initCredentials(String credentialsFilename) {
		StringBuilder buffer = new StringBuilder();
		if (!loadFile(credentialsFilename, buffer)) {
			System.err.println("error: unable to load file " + credentialsFilename);
			return false;
		}

		String credentials = buffer.toString().trim();
		if (credentials == null) {
			System.err.println("error: could not decrypt credentials");
			return false;
		}

		String[] lines = credentials.trim().split("\n");
		if (lines.length != 2) {
			System.err.println("error: wrong number of lines in credentials");
			return false;
		}

		String user = lines[0].trim();
		if (user.isBlank()) {
			System.err.println("error: user credential invalid");
			return false;
		}

		String password = lines[1].trim();
		if (password.isBlank()) {
			System.err.println("error: password credential empty");
			return false;
		}

		_user = user;
		_password = password;

		return true;
	}

	/**
	 * Method determines if string parameters are equal. Null comparisons are always
	 * false.
	 * 
	 * @param stringA string to be compared.
	 * @param stringB string to be compared.
	 * @return boolean true if parameters stringA and stringB are equal and both are
	 *         not null.
	 */
	private boolean isEqualNotNull(String stringA, String stringB) {
		if (stringA == null || stringB == null) {
			return false;
		}
		return stringA.compareTo(stringB) == 0;
	}

	/**
	 * Method sets server {@link java.security.PublicKey} object by reading it from
	 * file.
	 * 
	 * @param serverPublicKeyFilename location of file containing
	 *                                {@link java.security.PublicKey}.
	 * @return boolean indicating success or failure.
	 */
	private boolean initServerPublicKeyFromFile(String serverPublicKeyFilename) {
		_serverPublicKey = getPublicKeyFromFile(serverPublicKeyFilename);
		return _serverPublicKey != null;
	}

	/**
	 * Method sets server {@link java.security.PublicKey} object by reading it from
	 * server.
	 * 
	 * @return boolean indicating success or failure.
	 */
	private boolean initServerPublicKeyFromServer() {
		if (!getPublicKeyFromServer()) {
			System.err.println("error: getPublicIpFromServer failed");
			return false;
		}
		return true;
	}

	/**
	 * Method validates whether parameter inet4Ip is a valid iPv4 address. Method
	 * returns true if yes, false otherwise.
	 *
	 * @param inet4Ip the iPv4 address value to be checked.
	 * @return boolean indicating whether parameter inet4Ip was valid or not.
	 */
	private boolean isValidInet4Address(String inet4Ip) {
		if (inet4Ip == null || inet4Ip.isBlank()) {
			return false;
		}
		return IpConfig.CONSTANT_IPV4_REGEXP_PATTERN.matcher(inet4Ip == null ? "" : inet4Ip).matches();
	}

	/**
	 * Method loads file named in filename parameter. The contents of the file are
	 * returned in the buffer argument.
	 * 
	 * @param filename name of file to be loaded.
	 * @param buffer   file contents are returned in buffer parameter.
	 * @return boolean indicating whether file contents were loaded into buffer
	 *         parameter successfully.
	 */
	private boolean loadFile(String filename, StringBuilder buffer) {

		File file = new File(filename);

		if (!file.exists() || !file.canRead()) {
			System.err.println("error: filename '" + filename + "' not accessible");
			return false;
		}

		FileInputStream inputStream = null;

		try {
			inputStream = new FileInputStream(file);

			if (file.length() < IpConfig.CONSTANT_MAXIMUM_ALLOWED_FILESIZE_BYTES) {
				byte bytes[] = new byte[(int) file.length()];
				inputStream.read(bytes);
				String data = new String(bytes, StandardCharsets.UTF_8);
				inputStream.close();
				buffer.append(data);
				return true;
			}

			System.err.println("error: file is larger than maximum allowed size of "
					+ IpConfig.CONSTANT_MAXIMUM_ALLOWED_FILESIZE_BYTES + " bytes - " + file.length());

		} catch (FileNotFoundException e) {
			System.err.println("exception: loadFile[1] " + e.getClass().getName() + " - " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		} catch (IOException e) {
			System.err.println("exception: loadFile[2] " + e.getClass().getName() + " - " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		}

		try {
			if (inputStream != null) {
				inputStream.close();
			}
		} catch (IOException e) {
			System.err.println("exception: loadFile[2] " + e.getClass().getName() + " - " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
		}

		return false;
	}

	/**
	 * Method calls the server to request that the server updates ip permissions.
	 * The client sends a random value and the ip address to be added to the server
	 * permissions. The return code from the server is checked to ensure that it is
	 * {@value java.net.HttpURLConnection#HTTP_OK}. If anything other than
	 * {@value java.net.HttpURLConnection#HTTP_OK} is returned by the server this
	 * method returns false, otherwise true.
	 * 
	 * @param publicIp the ip address to be sent to the server for permission
	 *                 changes.
	 * @return boolean indicating whether the process worked or not.
	 */
	private boolean setPublicIpOnServer(String publicIp) {

		StringBuilder responseBuffer = new StringBuilder();
		Map<String, String> requestData = new HashMap<String, String>();

		if (!buildServerMessageData(requestData, getRandom(), publicIp)) {
			System.err.println("error: unable to build message data");
			return false;
		}

		try {
			int code = doPost(IpConfig.ipConfig().getSetUrl(), responseBuffer, requestData);
			if (code != HttpURLConnection.HTTP_OK) {
				System.err.println("error: call to server set ip failed - code " + Integer.toString(code));
				return false;
			}
		} catch (Exception e) {
			System.err.println("exception: getCurrentIp " + e.getClass().getName() + ": " + e.getMessage());
			if (IpConfig.ipConfig().getDebug()) {
				e.printStackTrace();
			}
			return false;
		}

		return true;
	}

	/**
	 * Boolean indicating whether this {@link IpClient} object is in a valid state.
	 */
	private boolean _isValid = false;

	/**
	 * {@link java.security.KeyFactory} used to generate
	 * {@link java.security.PrivateKey} and {@link java.security.PublicKey}.
	 */
	private KeyFactory _keyFactory = null;

	/**
	 * Client's {@link java.security.PrivateKey} located in
	 * {@link IpConfig#_clientPrivateKey}.
	 */
	private PrivateKey _clientPrivateKey = null;

	/**
	 * Client's {@link java.security.PublicKey} located in
	 * {@link IpConfig#_clientPublicKey}.
	 */
	private PublicKey _clientPublicKey = null;

	/**
	 * {@link java.util.Map} containing split client {@link java.security.PublicKey}
	 * internal {@link java.util.Base64} string value.
	 */
	Map<String, String> _clientPublicKeySubstrings = new HashMap<String, String>();

	/**
	 * Server's {@link java.security.PublicKey} located in
	 * {@link IpConfig#_serverPublicKey}.
	 */
	private PublicKey _serverPublicKey = null;

	/**
	 * Client's server user id, located in {@link IpConfig#_credentials} in
	 * encrypted form.
	 */
	private String _user = null;

	/**
	 * Client's server password - located in {@link IpConfig#_credentials} in
	 * encrypted form.
	 */
	private String _password = null;

	/**
	 * {@link java.net.http.HttpClient} object for calls to server.
	 */
	private static final HttpClient _httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
			.connectTimeout(Duration.ofSeconds(IpConfig.CONSTANT_HTTP_TIMEOUT_SECONDS)).build();

}
