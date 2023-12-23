
package cc.tools.dynip.client;

// TODO
// 1. change package
// 2. rederaft each function
// 3. generate javadoc

import java.util.*;
import java.util.regex.*;

/**
 * This class manages program command line and configuration values
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public class IpConfig {
	/**
	 * Constructor for {@link IpConfig}. This is private and should only be used by
	 * this class when creating a global singleton instance.
	 */
	private IpConfig() {
	}

	/**
	 * Method returns {@link IpConfig} singleton.
	 * 
	 * @return {@link IpConfig} containing current configuration. Method
	 *         {@link #loadParameters(String[])} must be called first.
	 */
	public static IpConfig ipConfig() {
		return IpConfig._ipConfig;
	}

	/**
	 * Method displays table showing configured values.
	 */
	public void doDump() {
		System.out.println(new Date() + ": configuration");
		System.out.println("-protocol:           " + getProtocol());
		System.out.println("-hostname:           " + getHostname());
		System.out.println("-port:               " + getPort());
		System.out.println("-uri:                " + getURI());
		System.out.println("-credentials:        " + getCredentials());
		System.out.println("-client-private-key: " + (getClientPrivateKey().isBlank() ? "<generated>" : getClientPrivateKey()));
		System.out.println("-client-public-key:  " + (getClientPublicKey().isBlank() ? "<generated>" : getClientPublicKey()));
		System.out.println("-server-public-key:  " + (getServerPublicKey().isBlank() ? "<from server>" : getServerPublicKey()));
		System.out.println("-debug:              " + (getDebug() ? "true" : "false"));
	}

	/**
	 * Method displays 'usage' help information showing command-line options.
	 */
	public void doHelp() {
		System.out.println("usage:");
		System.out.print(" [-protocol (http|https)] -hostname (ip|domain) [-port <port>] [-uri <path>] ");
		System.out.print("-client-private-key <file> -client-public-key <file> -server-public-key <file> ");
		System.out.println("-credentials <file> [-debug]");
		System.out.println("-protocol:           optional.  set to http or https. default https.");
		System.out.println("-hostname:           mandatory. server host. can be an ip address or name.");
		System.out.println("-port:               optional.  server port. default 80/443 based on protocol.");
		System.out.println("-uri:                optional.  url server endpoint prefix. default '/ipserver/server/ip'.");
		System.out.println("-credentials:        mandatory. credentials for server access.");
		System.out.println("-client-private-key: optional.  client's private key file. if either private or public client file param is missing, both are generated.");
		System.out.println("-client-public-key:  optional.  client's public key file. if either private or public client file param is missing, both are generated.");
		System.out.println("-server-public-key:  optional.  server's public key file. if not set it is obtained from server.");
		System.out.println("-debug:              optional.  toggle to adjust debug mode. default false.");
	}

	/**
	 * Method returns {@link #_clientPrivateKey} filename configuration value.
	 * 
	 * @return {@link String} containing configured -client-private-key value.
	 */
	public String getClientPrivateKey() {
		return _clientPrivateKey;
	}

	/**
	 * Method returns {@link #_clientPublicKey} filename configuration value.
	 * 
	 * @return {@link String} containing configured -client-public-key value.
	 */
	public String getClientPublicKey() {
		return _clientPublicKey;
	}	

	/**
	 * Method returns {@link #_credentials} filename onfiguration value.
	 * 
	 * @return {@link String} containing -credentials string.
	 */
	public String getCredentials() {
		return _credentials;
	}

	/**
	 * Method returns {@link #_debug} configuration value.
	 * 
	 * @return boolean indicating whether debug mode is on or not.
	 */
	public boolean getDebug() {
		return _debug;
	}

	/**
	 * Method returns {@code List<String>} containing configuration processing
	 * errors.
	 * 
	 * @return {@code List<String>} containing errors raised during command line
	 *         parameter processing.
	 */
	public List<String> getErrors() {
		List<String> errors = new ArrayList<String>();
		errors.addAll(_errors);
		return errors;
	}

	/**
	 * Method returns url for server 'Get' endpoint
	 * 
	 * @return {@link String} containing 'get' endpoint url value
	 */
	public String getGetUrl() {
		StringBuilder buffer = new StringBuilder();
		buffer.append(getBaseUrl());
		buffer.append("/get");
		return buffer.toString();
	}

	/**
	 * Method returns url for server 'Certificate' endpoint
	 * 
	 * @return {@link String} containing 'get' endpoint url value
	 */
	public String getCertificateUrl() {
		StringBuilder buffer = new StringBuilder();
		buffer.append(getBaseUrl());
		buffer.append("/certificate");
		return buffer.toString();
	}

	/**
	 * Method returns {@link #_hostname} configuration value.
	 * 
	 * @return {@link String} containing parameter -hostname value.
	 */
	public String getHostname() {
		return _hostname;
	}

	/**
	 * Method returns {@link #_isHelp} value.
	 * 
	 * @return boolean indicating whether help command line option is present.
	 */
	public boolean getIsHelp() {
		return _isHelp;
	}

	/**
	 * Method returns {@link #_port} configuration value.
	 * 
	 * @return int containing configured -port value.
	 */
	public int getPort() {
		return _port;
	}

	/**
	 * Method returns {@link #_protocol} configuration value.
	 * 
	 * @return {@link String} containing -protocol value.
	 */
	public String getProtocol() {
		return _protocol;
	}

	/**
	 * Method returns {@link #_serverPublicKey} filename configuration value.
	 * 
	 * @return {@link String} containing configured -server-public-key value.
	 */
	public String getServerPublicKey() {
		return _serverPublicKey;
	}

	/**
	 * Method returns url for server 'Set' endpoint.
	 * 
	 * @return {@link String} containing 'set' endpoint url value.
	 */
	public String getSetUrl() {
		StringBuilder buffer = new StringBuilder();
		buffer.append(getBaseUrl());
		buffer.append("/set");
		return buffer.toString();
	}

	/**
	 * Method returns {@link #_uri} configuration value.
	 * 
	 * @return {@link String} containing configured -uri value.
	 */
	public String getURI() {
		return _uri;
	}

	/**
	 * Method returns {@link #_isValid} value.
	 * 
	 * @return boolean indicating whether configuration is valid or not.
	 */
	public boolean isValid() {
		return _isValid;
	}

	/**
	 * Method returns boolean indicating whether args variable contains the help
	 * command line indicator '-h'.
	 * 
	 * @param args {@code String[]} containing command line arguments.
	 * 
	 * @return boolean indicating whether help command line option has been
	 *         requested.
	 */
	public boolean isHelp(String[] args) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].compareToIgnoreCase("-h") == 0) {
				_isHelp = true;
				return true;
			}
		}
		return false;
	}

	/**
	 * Method loads configuration from file and returns boolean indicating result of
	 * loading and processing command line arguments.
	 * 
	 * @param args {@code String[]} containing command line arguments.
	 * 
	 * @return boolean indicating whether load was successful.
	 */
	public boolean loadParameters(String[] args) {
		Map<String, String> values = new HashMap<String, String>();

		if (!processParameters(args, values)) {
			return false;
		}

		if (!setClientPrivateKey(values) | !setClientPublicKey(values) | !setDebug(values) | !setHostname(values)
				| !setProtocol(values) | !setPort(values) | !setServerPublicKey(values) | !setCredentials(values)
				| !setURI(values)) {
			return false;
		}

		for (String parameterName : IpConfig.CONSTANT_PARAMETERS_ALL) {
			values.remove(parameterName);
		}

		if (!values.keySet().isEmpty()) {
			for (String key : values.keySet()) {
				_errors.add("invalid parameter '" + key + "'");
			}
			return false;
		}

		if (_clientPublicKey.isBlank() ||
				_clientPrivateKey.isBlank()) {
			_clientPublicKey = "";
			_clientPrivateKey = "";
		}
		
		_isValid = true;
		
		return true;
	}

	/**
	 * Method returns server's Url base value.
	 * 
	 * @return {@link String} containing base url.
	 */
	private String getBaseUrl() {
		StringBuilder buffer = new StringBuilder();
		buffer.append(getProtocol());
		buffer.append("://");
		buffer.append(getHostname());
		buffer.append(":");
		buffer.append(getPort());
		buffer.append(getURI());
		return buffer.toString();
	}

	/**
	 * Method returns a boolean indicating whether the parameter token is a valid
	 * token. Each text value read into the problem from an external source should
	 * be checked by this method. Only a very limited set of characters are
	 * white-listed and allowed. Errors are written to the errors parameter for
	 * access by the caller.
	 *
	 * @param token  the String token value to be checked.
	 * @param errors any errors are written to this variable.
	 * @return boolean indicating whether parameter token is a valid input value or
	 *         not.
	 */
	private static boolean isValidToken(String token, List<String> errors) {
		for (char c : token.toCharArray()) {
			if (!(Character.isLetterOrDigit(c) || c == '/' || c == '\\' || c == '.' || c == '-' || c == '_')) {
				errors.add("invalid character '" + c + "' found in token '" + token + "'");
				return false;
			}
		}
		return true;
	}

	/**
	 * Method to store 'mandatory parameter missing' error.
	 * 
	 * @param parameterName name of parameter to report.
	 */
	private void logMissingParameterError(String parameterName) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("mandatory parameter -");
		buffer.append(parameterName);
		buffer.append(" missing");
		_errors.add(buffer.toString());
	}
	
	/**
	 * Method returns boolean indicating argument transformation succeeded or not.
	 * Values in command line arguments 'args' variable will be transformed into
	 * name/value pairs and deposited in results parameter.
	 * 
	 * @param args    String array containing command line arguments.
	 * @param results Array within which transformed results will be placed.
	 * @return boolean true indicating argument transformation worked, false
	 *         otherwise.
	 */
	private boolean processParameters(String[] args, Map<String, String> results) {
		String name = null;
		for (int i = 0; i < args.length; i++) {
			String token = args[i].trim();
			if (name == null || (!token.isEmpty() && token.charAt(0) == '-')) {
				token = token.toLowerCase();
				if (token.length() < 2) {
					_errors.add("empty value at position " + Integer.toString(i) + " '" + args[i] + "'");
					return false;
				}
				if (token.charAt(0) != '-') {
					_errors.add("ill-formed value at position " + Integer.toString(i) + " '" + args[i] + "'");
					return false;
				}
				name = token.substring(1);
				if (results.containsKey(name)) {
					_errors.add("duplicate value at position " + Integer.toString(i) + " '" + args[i] + "'");
					return false;
				}
				if (!isValidToken(name, _errors)) {
					_errors.add("invalid name at position " + Integer.toString(i) + " '" + args[i] + "'");
					return false;
				}
				results.put(name, "");
			} else {
				if (!isValidToken(token, _errors)) {
					_errors.add("invalid name at position " + Integer.toString(i) + " '" + args[i] + "'");
					return false;
				}
				results.put(name, token);
				name = null;
			}
		}
		return true;
	}

	/**
	 * Method sets optional parameter {@link CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY}
	 * {@value CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY}. if either client public or client
	 * private key is not supplied then a newpublic/private pair will be generated and used.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setClientPrivateKey(Map<String, String> values) {
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY)) {
			_clientPrivateKey = values.get(IpConfig.CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY);
			return true;
		}

		_clientPrivateKey = "";
		return true;
	}

	/**
	 * Method sets optional parameter {@link CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY}
	 * {@value CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY}. if either client public or client
	 * private key is not supplied then a new public/private pair will be generated and used.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setClientPublicKey(Map<String, String> values) {
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY)) {
			_clientPublicKey = values.get(IpConfig.CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY);
			return true;
		}

		_clientPublicKey = "";
		return true;
	}

	/**
	 * Method sets mandatory parameter {@link CONSTANT_PARAMETER_CREDENTIALS}
	 * {@value CONSTANT_PARAMETER_CREDENTIALS}.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setCredentials(Map<String, String> values) {
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_CREDENTIALS)) {
			_credentials = values.get(IpConfig.CONSTANT_PARAMETER_CREDENTIALS);
			return true;
		}

		logMissingParameterError(IpConfig.CONSTANT_PARAMETER_CREDENTIALS);
		return false;
	}

	/**
	 * Method sets optional parameter {@link CONSTANT_PARAMETER_DEBUG}
	 * {@value CONSTANT_PARAMETER_DEBUG}.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setDebug(Map<String, String> values) {
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_DEBUG)) {
			String value = values.get(IpConfig.CONSTANT_PARAMETER_DEBUG);
			if (!(value == null || value.isBlank() || value.isEmpty())) {

				StringBuilder buffer = new StringBuilder();
				buffer.append("flag parameter -");
				buffer.append(IpConfig.CONSTANT_PARAMETER_DEBUG);
				buffer.append(" should not have a value");
				_errors.add(buffer.toString());

				return false;
			}
			_debug = true;
			return true;
		}

		_debug = false;
		return true;
	}

	/**
	 * Method sets mandatory parameter {@link CONSTANT_PARAMETER_HOSTNAME}
	 * {@value CONSTANT_PARAMETER_HOSTNAME}. Can be ip address or domain name.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setHostname(Map<String, String> values) {
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_HOSTNAME)) {
			_hostname = values.get(IpConfig.CONSTANT_PARAMETER_HOSTNAME);
			return true;
		}

		logMissingParameterError(IpConfig.CONSTANT_PARAMETER_HOSTNAME);
		return false;
	}

	/**
	 * Method sets optional parameter {@link CONSTANT_PARAMETER_PORT}
	 * {@value CONSTANT_PARAMETER_PORT} Port value must be more than 0. parameter
	 * Port defaults to default port for protocol setting - either '80' or '443'.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setPort(Map<String, String> values) {
		int port = -1;

		if (_protocol.compareTo("http") == 0) {
			port = 80;
		} else if (_protocol.compareTo("https") == 0) {
			port = 443;
		} else {
			StringBuilder buffer = new StringBuilder();
			buffer.append("internal error: ");
			buffer.append(IpConfig.CONSTANT_PARAMETER_PROTOCOL);
			buffer.append(" must be set to 'http' or 'https' before ");
			buffer.append(IpConfig.CONSTANT_PARAMETER_PORT);
			buffer.append(" can be set");
			_errors.add(buffer.toString());
			return false;
		}

		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_PORT)) {
			try {
				port = Integer.parseInt(values.get(IpConfig.CONSTANT_PARAMETER_PORT));
			} catch (NumberFormatException e) {
				_errors.add("-" + IpConfig.CONSTANT_PARAMETER_PORT + " is invalid number");
				return false;
			}
		} else {
			values.put(IpConfig.CONSTANT_PARAMETER_PORT, Integer.toString(port));
		}

		_port = port;
		if (_port < 0) {
			StringBuilder buffer = new StringBuilder();
			buffer.append("-");
			buffer.append(IpConfig.CONSTANT_PARAMETER_PORT);
			buffer.append(" is not a valid port number - found ");
			buffer.append(_port);
			buffer.append(" from '");
			buffer.append(values.get(IpConfig.CONSTANT_PARAMETER_PORT));
			buffer.append("' and '");
			buffer.append(_port);
			buffer.append("'");
			_errors.add(buffer.toString());

			return false;
		}

		return true;
	}

	/**
	 * Method sets optional parameter {@link CONSTANT_PARAMETER_PROTOCOL}
	 * {@value CONSTANT_PARAMETER_PROTOCOL}. Can be 'http' or 'https'.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setProtocol(Map<String, String> values) {
		String protocol = null;
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_PROTOCOL)) {
			protocol = values.get(IpConfig.CONSTANT_PARAMETER_PROTOCOL);
			if (protocol.compareTo("http") != 0 && protocol.compareTo("https") != 0) {
				_errors.add("-" + IpConfig.CONSTANT_PARAMETER_PROTOCOL + " must be value 'http' or 'https'");
				return false;
			}
		} else {
			protocol = "https";
			values.put(CONSTANT_PARAMETER_PROTOCOL, protocol);
		}

		_protocol = protocol;
		return true;
	}
	
	/**
	 * Method sets mandatory parameter {@link CONSTANT_PARAMETER_SERVER_PUBLIC_KEY}
	 * {@value CONSTANT_PARAMETER_SERVER_PUBLIC_KEY}. if not present this is fetched from
	 * the server during startup.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setServerPublicKey(Map<String, String> values) {
		if (values.containsKey(CONSTANT_PARAMETER_SERVER_PUBLIC_KEY)) {
			_serverPublicKey = values.get(CONSTANT_PARAMETER_SERVER_PUBLIC_KEY);
			return true;
		}

		_serverPublicKey = "";
		return true;
	}
	
	/**
	 * Method sets optional parameter {@link CONSTANT_PARAMETER_URI}
	 * {@value CONSTANT_PARAMETER_URI}.
	 * 
	 * @param values contains all loaded config parameter values.
	 * @return boolean indicating success or fail.
	 */
	private boolean setURI(Map<String, String> values) {
		String uri = null;
		if (values.containsKey(IpConfig.CONSTANT_PARAMETER_URI)) {
			uri = values.get(IpConfig.CONSTANT_PARAMETER_URI);
		} else {
			uri = "/ipserver/server/ip";
			values.put(IpConfig.CONSTANT_PARAMETER_URI, uri);
		}

		_uri = uri;
		return true;
	}

	/**
	 * Configured location of the client's {@link java.security.PrivateKey}.
	 */
	private String _clientPrivateKey = new String();

	/**
	 * Configured location of the client's {@link java.security.PublicKey}.
	 */
	private String _clientPublicKey = new String();

	/**
	 * Configured location of the users credentials file.
	 */
	private String _credentials = new String();

	/**
	 * Configured flag for additional debug output.
	 */
	private boolean _debug = false;

	/**
	 * {@code List<String>} containing a list of errors encountered during loading
	 * of command line parameters by method {@link #loadParameters(String[])}.
	 */
	private List<String> _errors = new ArrayList<String>();

	/**
	 * Configured server name. Use Ip address (IPv4 only) or name.
	 */
	private String _hostname = new String();

	/**
	 * Singleton {@link IpConfig} object.
	 */
	private static IpConfig _ipConfig = new IpConfig();

	/**
	 * Configured flag indicating whether help has been requested on command line.
	 */
	private boolean _isHelp = false;

	/**
	 * Configured flag indicating whether {@link IpConfig} is valid or not.
	 */
	private boolean _isValid = false;

	/**
	 * Configured server port.
	 */
	private int _port = -1;

	/**
	 * Configured connection protocol. Must be either 'http' or 'https'. 'https'
	 * requires a valid authority signed ssl certificate on the server.
	 */
	private String _protocol = new String();

	/**
	 * Configured location of the server's {@link java.security.PublicKey}.
	 */
	private String _serverPublicKey = new String();

	/**
	 * Configured servlet Uri prefix value.
	 */
	private String _uri = new String();

	/**
	 * {@link javax.crypto.Cipher} transformation type '{@value CONSTANT_CYPHER_TRANSFORMATION}'.
	 */
	final public static String CONSTANT_CYPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

	/**
	 * Regular expression value used by regular expression to validate iP4v ip addresses.
	 */
	final public static Pattern CONSTANT_IPV4_REGEXP_PATTERN = Pattern
			.compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
					+ "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	/**
	 * {@link java.security.KeyFactory} algorithm '{@value CONSTANT_KEY_ALGORITHM_RSA}'.
	 */
	final public static String CONSTANT_KEY_ALGORITHM_RSA = "RSA";

	/**
	 * '{@value CONSTANT_KEY_ALGORITHM_RSA}' key length '{@value CONSTANT_KEY_ALGORITHM_RSA_KEY_LENGTH}'.
	 */
	final public static int CONSTANT_KEY_ALGORITHM_RSA_KEY_LENGTH = 4096;

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_USER}'.
	 */
	final public static String CONSTANT_HTTP_KEY_USER = "user";

        /**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_PASSWORD}'.
	 */
	final public static String CONSTANT_HTTP_KEY_PASSWORD = "password";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_HEADER}'.
	 */
	final public static String CONSTANT_HTTP_KEY_HEADER = "header";

	/**
	 * HTTP message key prefix '{@value CONSTANT_HTTP_KEY_PART_N}' for client key
	 * substrings.
	 */
	final public static String CONSTANT_HTTP_KEY_PART_N = "key-part-";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_PUBLIC_IP}'.
	 */
	final public static String CONSTANT_HTTP_KEY_PUBLIC_IP = "public-ip";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_TOTAL}'.
	 */
	final public static String CONSTANT_HTTP_KEY_TOTAL = "key-part-total";

	/**
	 * HTTP timeout '{@value CONSTANT_HTTP_TIMEOUT_SECONDS}' seconds.
	 **/
	final public static int CONSTANT_HTTP_TIMEOUT_SECONDS = 10;

	/**
	 * Maximum allowed file size -
	 * '{@value CONSTANT_MAXIMUM_ALLOWED_FILESIZE_BYTES}' bytes.
	 **/
	final public static int CONSTANT_MAXIMUM_ALLOWED_FILESIZE_BYTES = 10240;

	/**
	 * RSA encode size limit. NOTE: all keys used in this program are 4096 long so
	 * limits the encode buffer to RSA (length % 8) = (11 padding bits)) =
	 * '{@value CONSTANT_MAXIMUM_RSA_ENCODE_BUFFER_LENGTH}'.
	 **/
	final public static int CONSTANT_MAXIMUM_RSA_ENCODE_BUFFER_LENGTH = 500;

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY}'.
	 */
	final public static String CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY = "client-private-key";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY}'.
	 */
	final public static String CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY = "client-public-key";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_CREDENTIALS}'.
	 */
	final public static String CONSTANT_PARAMETER_CREDENTIALS = "credentials";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_DEBUG}'.
	 */
	final public static String CONSTANT_PARAMETER_DEBUG = "debug";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_HOSTNAME}'.
	 */
	final public static String CONSTANT_PARAMETER_HOSTNAME = "hostname";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_PORT}'.
	 */
	final public static String CONSTANT_PARAMETER_PORT = "port";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_PROTOCOL}'.
	 */
	final public static String CONSTANT_PARAMETER_PROTOCOL = "protocol";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_SERVER_PUBLIC_KEY}'.
	 */
	final public static String CONSTANT_PARAMETER_SERVER_PUBLIC_KEY = "server-public-key";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_URI}'.
	 */
	final public static String CONSTANT_PARAMETER_URI = "uri";

	/**
	 * Parameter array containing all parameter constants.
	 */
	final public static String[] CONSTANT_PARAMETERS_ALL = new String[] { CONSTANT_PARAMETER_PROTOCOL,
			CONSTANT_PARAMETER_HOSTNAME, CONSTANT_PARAMETER_PORT, CONSTANT_PARAMETER_URI,
			CONSTANT_PARAMETER_CLIENT_PRIVATE_KEY, CONSTANT_PARAMETER_CLIENT_PUBLIC_KEY,
			CONSTANT_PARAMETER_SERVER_PUBLIC_KEY, CONSTANT_PARAMETER_CREDENTIALS, CONSTANT_PARAMETER_DEBUG };

}
