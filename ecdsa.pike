/*
 * ecdsa.pike: Functions concerning the EcdsaVerify tests.
 *
 * The SECP521R1, SECP384R1, SECP256R1, and SECP224R1 curves are
 * currently supported, however the latter one is not supported in all
 * versions of Pike.
 */


/*
 * The main test for EcdsaVerify tests.
 * This function simply sets the public key, then verifies the message
 * and signature.
 * The function returns whether the test was successful(true) or not.
 */
bool ecdsa_test(mapping test, string algorithm) {
	mixed curve = lookup_init(algorithm);
	mixed key = test["key"];

	begin_ever(test["tcId"], test["comment"]);

	switch(test["curve"]) {
		case "secp521r1":
			curve = curve.SECP_521R1;
			break;
		case "secp384r1":
			curve = curve.SECP_384R1;
			break;
		case "secp256r1":
			curve = curve.SECP_256R1;
			break;
		case "secp224r1": 
#if constant(Crypto.ECC.SECP_224R1)
			curve = curve.SECP_224R1;
			break;
#endif
		case "secp256k1":
		case "secp224k1":
		case "brainpoolP224r1":
		case "brainpoolP224t1":
		case "brainpoolP256r1":
		case "brainpoolP256t1":
		case "brainpoolP320r1":
		case "brainpoolP320t1":
		case "brainpoolP384r1":
		case "brainpoolP384t1":
		case "brainpoolP512r1":
		case "brainpoolP512t1":
			DBG("Skipping test tcId %d due to un-supported curve %s.", test["tcId"], test["curve"]);
			return true;
		default:
			log_err(DBG_ERROR, false, "Unknown curve in tcId %d: %s.", test["tcId"], test["curve"]);
			return false;
	}

	mixed ECDSA = curve->ECDSA();
	ECDSA->set_public_key(Gmp.mpz(key["wx"], 16), Gmp.mpz(key["wy"], 16));

	mixed sha = get_sha_function(test["sha"]);

	bool ret = false;

	array err = catch { ret = ECDSA->pkcs_verify(test["msg"], sha, test["sig"]); };

	if(err) {
		if(test["result"] == "valid") {
			log_err(DBG_ERROR, false, "Unexpected error on a valid testcase tcId %d: %O.", test["tcId"], err);
			return false;
		}
		DBG("GENERAL PASS");
		return true;
	}

	if(test["result"] == "invalid") {
		if(ret) {
			log_err(DBG_ERROR, false, "Unexpected verify on an invalid testcase tcId %d.", test["tcId"]);
			return false;
		}
	} else {
		if(!ret && test["result"] != "acceptable") {
			log_err(DBG_ERROR, false, "Unexpected failure on a seemingly valid testcase tcId %d.", test["tcId"]);
			return false;
		}
	}

	DBG("GENERAL PASS");
	return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with ECDSA-type tests, and returns the number of failed tests.
 */
int ecdsa_tests(mapping testGroup, string algorithm) {
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

		if(!ecdsa_test(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
