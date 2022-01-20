/*
 * rsa_decrypt.pike: Functions concerning the RsaesPkcs1Decrypt tests.
 */

/*
 * The main test for RsaesPkcs1Decrypt tests.
 * This function sets the private key, then attempts to decrypt the ct.
 * It then compares the provided ct with the decrypted ct.
 * The function returns whether the test was successful(true) or not.
 */
bool rsa_decrypt_test(mapping test, string algorithm) {
	begin_ever(test["tcId"], test["comment"]);

	mixed state = lookup_init(algorithm)(test["privateKeyPkcs8"]);

	string ret;
	array err = catch { ret = state->decrypt(test["ct"]); };

	if(err && test["result"] == "valid") {
		log_err(DBG_ERROR, false, "Error while decrypting tcId %d: (%O).", test["tcId"], err);
		return false;
	}

	if(test["msg"] == ret) {
		if(test["result"] == "invalid") {
			log_err(DBG_ERROR, false, "Msg match on seemingly invalid case tcId %d.", test["tcId"]);
			return false;
		}
	} else {
		if(test["result"] == "valid") {
			log_err(DBG_ERROR, false, "Msg mismatch on seemingly valid case tcId %d.", test["tcId"]);
			return false;
		}
	}

	DBG("GENERAL PASS");
	return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with RSA/PKCS1-type tests, and returns the number of failed tests.
 */
int rsa_decrypt_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	string privateKeyPkcs8 = String.hex2string(testGroup["privateKeyPkcs8"]);

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		handle_special_actions(test, algorithm);

		test["privateKeyPkcs8"] = privateKeyPkcs8;

		if(!rsa_decrypt_test(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
