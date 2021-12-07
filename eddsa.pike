/*
 * eddsa.pike: Functions concerning the EddsaVerify tests.
 *
 * The Curve25519 and Curve448 algorithms are currently only available
 * in Pike 8.1.
 */

/* The main test for EddsaVerify tests.
 * This function simply sets the public key, then verifies the message
 * and signature.
 * The function returns whether the test was successful(true) or not.
 */
bool eddsa_test(mapping test, string algorithm) {
	mixed curve = lookup_init(algorithm);
	mixed key = test["key"];

	begin_ever(test["tcId"], test["comment"]);

	switch(key["curve"]) {
		case "edwards25519":
			curve = curve.Curve25519;
			break;
		case "edwards448":
			curve = curve.Curve448;
			break;
		default:
			log_err(DBG_ERROR, false, "Unknown curve in tcId %d: %s.", test["tcId"], test["curve"]);
			return false;
	}

	mixed eddsa = curve.EdDSA();

	eddsa->set_public_key(String.hex2string(key["pk"]));

	eddsa->pkcs_verify(test["msg"], 0, test["sig"]);

	DBG("GENERAL PASS");
	return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with EDDSA-type tests, and returns the number of failed tests.
 */
int eddsa_tests(mapping testGroup, string algorithm) {
#if !constant(Crypto.ECC.Curve25519) || !constant(Crypto.ECC.Curve448)
	log_err(DBG_INFO, false, "Skipping EDDSA tests because Pike does not support it.");
	return 0;
#endif
	int numTests = sizeof(testGroup["tests"]);

	mapping key = testGroup["key"]; //unencoded EC Pubkey
	string sha = testGroup["sha"];
	string curve = key["curve"];

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		handle_special_actions(test, algorithm);

		test["key"] = key;
		test["sha"] = sha;
		test["curve"] = curve;

		if(!eddsa_test(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
