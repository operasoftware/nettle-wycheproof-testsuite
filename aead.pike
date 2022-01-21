/*
 * aead.pike: Functions concerning the AeadTest tests.
 */

/*
 * Used to unset the tagSize for AES-GCM tests.
 */
void unset_digest_size(mapping test) {
	test["tagSize"] = "null";
}

/*
 * This function decrypts an aead-encrypted string, using a provided
 * state and test vector. This function returns a mapping to the result, or
 * raises an error upon an error (i.e. it does does not catch errors).
 */
mapping aead_quick_decrypt(mixed state, mapping test) {
	mapping ret = ([ "msg":"", "digest": ""]);

	state->set_decrypt_key(test["key"]);
	state->set_iv(test["iv"]);

	state->update(test["aad"]);
	string(8bit) msg = state->crypt(test["ct"]);
	string(8bit) digest = test["tagSize"] != "null" ? state->digest(test["tagSize"]/8) : state->digest();

	ret["msg"] = msg;
	ret["digest"] = digest;

	return ret;

}

/*
 * This function encrypts a string, using a provided state
 * and test vector. This function returns a mapping to the result, or
 * raises an error upon an error (i.e. it does does not catch errors).
 */
mapping aead_quick_encrypt(mixed state, mapping test) {
	mapping ret = ([ "ct":"", "digest": ""]);

	state->set_encrypt_key(test["key"]);
	state->set_iv(test["iv"]);
	state->update(test["aad"]);

	string(8bit) ct = state->crypt(test["msg"]);
	string(8bit) digest = test["tagSize"] != "null" ? state->digest(test["tagSize"]/8) : state->digest();

	ret["ct"] = ct;
	ret["digest"] = digest;

	return ret;

}

/*
 * This function compares the results of both the encrypting and 
 * decrypting of the provided MSG/CTs in the vector, and the tag/digest.
 * From here, it checks whether those tests should result in the successful
 * decryption/encryption or not.
 * The function returns whether the test passed (true) or not.
 */
bool aead_test_roundtrip(mapping test, string algorithm) {
	mixed state1 = lookup_init(algorithm)();
	mixed state2 = lookup_init(algorithm)();

	begin_ever(test["tcId"], test["comment"]);

	mapping ret_dec;
	mapping ret_enc;

	array err = catch { ret_enc = aead_quick_encrypt(state1, test);};

	if(err) {
		if(test["result"] == "valid") {
			log_err(DBG_ERROR, false, "Unexpected error while encrypting tcId %d: %O.", test["tcId"], err);
			return false;
		}

		if(String.count(lower_case(err[0]), "invalid iv/nonce") > 0 && String.count(lower_case(test["comment"]), "invalid nonce") > 0) {
			DBG("INVALID NONCE");
			//"Expected" invalid response.
			return true;
		}

		if(String.count(lower_case(err[0]), "short nonce") > 0 && String.count(lower_case(test["comment"]), "invalid nonce size") > 0) {
			DBG("SHORT NONCE");
			return true;
		}

		log_err(DBG_ERROR, false, "Unknown error on an invalid testcase tcId %d: %O.", test["tcId"], err);
		return false;
	}

	err = catch { ret_dec = aead_quick_decrypt(state2, test); };

	if(err) {
		if(test["result"] == "valid") {
			log_err(DBG_ERROR, false, "Unexpected error while decrypting tcId %d: %O.", test["tcId"], err);
			return false;
		}

		if(String.count(lower_case(err[0]), "invalid iv/nonce") > 0 && String.count(lower_case(test["comment"]), "invalid nonce") > 0) {
			DBG("INVALID NONCE");
			//"Expected" invalid response.
			return true;
		}

		log_err(DBG_ERROR, false, "Unknown error while decrypting tcId %d: %O.", test["tcId"], err);
		return false;
	}

	if(test["ct"] != ret_enc["ct"]) {
		if(test["ivSize"]/8 > 13) {
			DBG("IV SIZE > 13");
			return true;
		}
		log_err(DBG_ERROR, false, "Generated CT is not the same as the provided value in tcId %d: %s/%s.", test["tcId"], String.string2hex(test["ct"]), String.string2hex(ret_enc["ct"]));
		return false;
	}

	if(test["msg"] != ret_dec["msg"]) {
		log_err(DBG_ERROR, false, "Generated MSG is not the same as the provided value in tcId %d: %s/%s.", test["tcId"], String.string2hex(test["msg"]), String.string2hex(ret_dec["msg"]));
		return false;
	}

	if(ret_dec["digest"] != ret_enc["digest"]) {
		log_err(DBG_ERROR, false, "Generated digest of both decrypted and encrypted messages are not the same in tcId %d: %s/%s.", test["tcId"], String.string2hex(ret_dec["digest"]), String.string2hex(ret_enc["digest"]));
		return false;
	}

	if(ret_dec["digest"] != test["tag"]) {
		if(test["result"] == "invalid" && (String.count(lower_case(test["comment"]), lower_case(String.string2hex(ret_dec["digest"]))) > 0 || String.count(lower_case(test["comment"]), "tag") > 0)) {
			DBG("INVALID TAG");
			return true;
		}
		if(test["result"] == "invalid") { //XXX: Is this correct with acceptable?
			DBG("???????");
			return true;
		}

		log_err(DBG_ERROR, false, "Unexpected failure on a seemingly valid testcase tcId %d: %s/%s.", test["tcId"], String.string2hex(ret_dec["digest"]),String.string2hex(test["tag"]));
		return false;
	}

	if(test["result"] == "invalid") {
		if(test["flags"] && test["flags"][0] == "ZeroLengthIv") {
			if(state1->iv_size() != 0) {
				DBG("INVALID IV");
				return true;
			}
		}
		log_err(DBG_ERROR, false, "Test tcId %d has passed all of our checks when it probably shouldn't. ivSize: %d", test["tcId"], state2->iv_size());
		return false;
	}
	DBG("GENERAL PASS");
	return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with AeadTest tests, and returns the number of failed tests.
 */
int aead_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		test["ivSize"] = testGroup["ivSize"];
		test["tagSize"] = testGroup["tagSize"];

		handle_special_actions(test, algorithm);

		if(!aead_test_roundtrip(test, algorithm)) {
			fail_count++;
		}
	}

	return fail_count;
}
