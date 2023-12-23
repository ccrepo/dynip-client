package cc.tools.dynip.client;

import org.junit.Test;
import org.junit.Assert;

import java.util.*;

public class IpConfigTest {

	/**
	 * Constructor.
	 */
	public IpConfigTest() {
	}

	/**
	 * Test method to check whether doHelp works if called before IpConfig init is
	 * called..
	 */
	@Test
	public void verifyDoHelp() {
		try {
			IpConfig ipConfig = IpConfig.ipConfig();
			ipConfig.doHelp();
		} catch (Exception e) {
			Assert.fail("exception calling doHelp on IpConfig before init " + e.getClass().toString());
		}
	}

	/**
	 * Test method to check whether paramter values are defaulted correctly.
	 */
	@Test
	public void verifyParameterLoad() {
		String[] array = { "-protocol", "http", "-hostname", "127.0.0.1", "-port", "80", "-uri", "/ipserver/uri",
				"-client-private-key", "/tmp/client-private.key", "-client-public-key", "/tmp/client-public.key",
				"-server-public-key", "/tmp/server-public.key", "-credentials", "/tmp/credentials", "-debug" };

		try {
			IpConfig.ipConfig().loadParameters(array);
		} catch (Exception e) {
			Assert.fail("exception calling init " + e.getClass().toString());
		}

		IpConfig ipConfig = IpConfig.ipConfig();
		List<String> errors = ipConfig.getErrors();

		if (!ipConfig.isValid()) {
			errors.add("config is invalid");
			checkErrors(errors);
		}

		checkValue("-protocol", IpConfig.ipConfig().getProtocol(), "http", errors);
		checkValue("-hostname", IpConfig.ipConfig().getHostname(), "127.0.0.1", errors);
		checkValue("-port", Integer.toString(IpConfig.ipConfig().getPort()), "80", errors);
		checkValue("-uri", IpConfig.ipConfig().getURI(), "/ipserver/uri", errors);
		checkValue("-client-private-key", IpConfig.ipConfig().getClientPrivateKey(), "/tmp/client-private.key", errors);
		checkValue("-client-public-key", IpConfig.ipConfig().getClientPublicKey(), "/tmp/client-public.key", errors);
		checkValue("-server-public-key", IpConfig.ipConfig().getServerPublicKey(), "/tmp/server-public.key", errors);
		checkValue("-credentials", IpConfig.ipConfig().getCredentials(), "/tmp/credentials", errors);
		checkValue("-debug", IpConfig.ipConfig().getDebug() ? "true" : "false", "true", errors);
		checkErrors(errors);
	}

	/**
	 * Test method to check whether optional paramter values are defaulted
	 * correctly.
	 */
	@Test
	public void verifyParameterLoadDefaults() {
		String[] array = { "-hostname", "localhost", "-client-private-key", "/tmp/client-private.key",
				"-client-public-key", "/tmp/client-public.key", "-server-public-key", "/tmp/server-public.key",
				"-credentials", "/tmp/credentials" };

		try {
			IpConfig.ipConfig().loadParameters(array);
		} catch (Exception e) {
			Assert.fail("exception calling init " + e.getClass().toString());
		}

		IpConfig ipConfig = IpConfig.ipConfig();
		List<String> errors = ipConfig.getErrors();

		if (!ipConfig.isValid()) {
			errors.add("config is invalid");
			checkErrors(errors);
		}

		checkValue("-protocol", IpConfig.ipConfig().getProtocol(), "https", errors);
		checkValue("-hostname", IpConfig.ipConfig().getHostname(), "localhost", errors);
		checkValue("-port", Integer.toString(IpConfig.ipConfig().getPort()), "443", errors);
		checkValue("-uri", IpConfig.ipConfig().getURI(), "/ipserver/server/ip", errors);
		checkValue("-client-private-key", IpConfig.ipConfig().getClientPrivateKey(), "/tmp/client-private.key", errors);
		checkValue("-client-public-key", IpConfig.ipConfig().getClientPublicKey(), "/tmp/client-public.key", errors);
		checkValue("-server-public-key", IpConfig.ipConfig().getServerPublicKey(), "/tmp/server-public.key", errors);
		checkValue("-credentials", IpConfig.ipConfig().getCredentials(), "/tmp/credentials", errors);
		checkValue("-debug", IpConfig.ipConfig().getDebug() ? "true" : "false", "false", errors);
		checkErrors(errors);
	}

	/**
	 * Utility method to check paramter extracted value against the expected
	 * value. If values differ a diagnostic error message is added to the errors
	 * parameter.
	 * 
	 * @return boolean false if value and expectedValue differ, true otherwise
	 */
	private boolean checkValue(String key, String value, String expectedValue, List<String> errors) {
		if (expectedValue.compareTo(value) != 0) {
			errors.add("key '" + key + "' value is '" + value + "' which differs from expected value '" + expectedValue
					+ "'");
			return false;
		}
		return true;
	}

	/**
	 * Utility method to check and report on errors in parameter errors. For each
	 * error an error string is prepared. This string is then used to report an
	 * error to JUnit framework.
	 * 
	 * @return boolean false if parameter errors contains data, true otherwise
	 */
	private boolean checkErrors(List<String> errors) {
		if (!errors.isEmpty()) {
			StringBuilder buffer = new StringBuilder();
			for (String error : errors) {
				if (!buffer.isEmpty()) {
					buffer.append("\n");
				}
				buffer.append(error);
			}

			if (!buffer.isEmpty()) {
				buffer.append("\n");
			}
			buffer.append("some values not correct.");
			Assert.fail(buffer.toString());
			return false;
		}
		return true;
	}
}
