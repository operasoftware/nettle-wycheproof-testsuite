/*
 *
 * aead.pike: Functions concerning the AeadTest tests.
 *
 * The AES-GCM, AES-EAX, AES-CCM, CHACHA20-POLY1305 algorithms
 * are currently supported. AEAD-AES-SIV-CMAC is currently missing.
 *
 * Copyright Opera Software, written by Joshua Rogers.
 *
 */

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
	string(8bit) digest = state->digest();

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
	string(8bit) digest = state->digest();

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
bool aead_test_roundtrip(mapping test, string algorithm, int ivSize) {
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

		if(String.count(err[0],"Invalid iv/nonce") > 0 && String.count(test["comment"], "invalid nonce") > 0) {
			//"Expected" invalid response.
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

		if(String.count(err[0],"Invalid iv/nonce") > 0 && String.count(test["comment"], "invalid nonce") > 0) {
			//"Expected" invalid response.
			return true;
		}

		log_err(DBG_ERROR, false, "Unknown error while decrypting tcId %d: %O.", test["tcId"], err);
		return false;
	}

	if(test["ct"] != ret_enc["ct"]) {
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
		if(test["result"] == "invalid" && String.count(test["comment"], String.string2hex(ret_dec["digest"])) > 0) {
			return true;
		}
		if(test["result"] == "invalid") { //XXX: Is this correct with acceptable?
			return true;
		}

		log_err(DBG_ERROR, false, "Unexpected failure on a seemingly valid testcase tcId %d: %s/%s.", test["tcId"], String.string2hex(ret_dec["digest"]),String.string2hex(test["tag"]));
		return false;
	}

	if(test["result"] == "invalid") {
		if(test["flags"] && test["flags"][0] == "ZeroLengthIv") {
			if(state1->iv_size() != 0) {
				return true;
			}
		}
		log_err(DBG_ERROR, false, "Test tcId %d has passed all of our checks when it probably shouldn't. ivSize: %d", test["tcId"], state2->iv_size());
		return false;
	}

	return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with AEAD-type tests, and returns the number of failed tests.
 */
int aead_tests(mapping testGroup, string algorithm) {
	int ivSize = testGroup["ivSize"];
	string type = testGroup["type"];
	int numTests = sizeof(testGroup["tests"]);

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];

		convert_test_to_string(test);

		if(!aead_test_roundtrip(test, algorithm, ivSize)) {
			fail_count++;
		}
	}

	return fail_count;
}
