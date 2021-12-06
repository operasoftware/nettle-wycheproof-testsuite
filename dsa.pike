/*
 *
 * dsa.pike: Functions concerning the DsaVerify tests.
 *
 * The DSA algorithm is currentl supported.
 *
 * Copyright Opera Software, written by Joshua Rogers.
 *
 */

bool dsa_test(mapping test, string algorithm) {
	mixed state1 = lookup_init(algorithm)();
	mixed key = test["key"];

	begin_ever(test["tcId"], test["comment"]);
	if(strlen(test["sig"]) == 0) return true;

	state1->set_public_key(Gmp.mpz(key["p"], 16), Gmp.mpz(key["q"], 16), Gmp.mpz(key["g"], 16), Gmp.mpz(key["y"], 16));

	mixed sha;
	switch(test["sha"]) {
		case "SHA-1":
			sha = Crypto.SHA1;
			break;
		case "SHA-224":
			sha = Crypto.SHA224;
			break;
		case "SHA-256":
			sha = Crypto.SHA256;
			break;
		default:
			log_err(DBG_ERROR, false, "Unknown SHA function in tcId %d (%s).", test["tcId"], test["sha"]);
			return false;
	}

	bool ret = false; //0=false, 1=true, 2=catch
	array err = catch { ret = state1->pkcs_verify(test["msg"], sha, test["sig"]); };

	if(err) {
		if(test["result"] == "valid") {
			log_err(DBG_ERROR, false, "Unexpected error on a valid testcase tcId %d.", test["tcId"]);
				return false;
		}

/*		if(String.count(lower_case(err[0]), "indefinite") && String.count(lower_case(test["comment"]), "indefinite")) {
			DBG("INDEFINITIVE LENGTH");
			return true;
		}

		if(String.count(lower_case(err[0]), "sizeof") && String.count(lower_case(test["comment"]), "length")) {
			DBG("INDEFINITIVE LENGTH");
			return true;
		}

		if(String.count(lower_case(err[0]), "end-of-content") && String.count(lower_case(test["comment"]), "pending")) {
			DBG("END-OF-CONTENT");
			return true;
		}

		if(String.count(lower_case(err[0]), "size") && String.count(lower_case(test["comment"]), "length")) {
			DBG("ILLEGAL SIZE");
			return true;
		}
*/
		DBG("GENERAL PASS");
		return true;
	}

	
	if(test["result"] == "invalid") {
		if(ret) {
			log_err(DBG_ERROR, false, "Successful verify on an invalid testcase tcId %d.", test["tcId"]);
			return false;
		}
	} else {
		if(!ret && test["result"] != "acceptable") {
			log_err(DBG_ERROR, false, "Unexpected failure on a seemingly valid testcase tcId %d: %O.", test["tcId"], ret);
			return false;
		}
	}

	DBG("GENERAL PASS");
	return true;
}

bool dsa_check_key(mapping test, string algorithm) {
	mixed state1 = lookup_init(algorithm)();
	mixed key = test["key"];

   state1->set_public_key(Gmp.mpz(key["p"], 16), Gmp.mpz(key["q"], 16), Gmp.mpz(key["g"], 16), Gmp.mpz(key["y"], 16));

	if(Gmp.mpz(key["p"], 16) != state1->get_p()) {
		log_err(DBG_ERROR, false, "Incorrect get_p() result");
		return false;
	}

	if(Gmp.mpz(key["g"], 16) != state1->get_g()) {
		log_err(DBG_ERROR, false, "Incorrect get_g() result");
		return false;
	}

	if(Gmp.mpz(key["q"], 16) != state1->get_q()) {
		log_err(DBG_ERROR, false, "Incorrect get_q() result");
		return false;
	}

	if(Gmp.mpz(key["y"], 16) != state1->get_y()) {
		log_err(DBG_ERROR, false, "Incorrect get_y() result");
		return false;
	}

	DBG("GENERAL PASS");
	return true;
}
/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with DSA-type tests, and returns the number of failed tests.
 */
int dsa_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	mapping key = testGroup["key"]; //unencoded DSA pubkey
	string keyDer = testGroup["keyDer"];
	string keyPem = testGroup["keyPem"];
	string sha = testGroup["sha"];
	
	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		handle_special_actions(test, algorithm);

		test["key"] = key;
		test["sha"] = sha;

		if(!dsa_test(test, algorithm) || !dsa_check_key(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
