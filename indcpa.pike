/*
 *
 * indcpa.pike: Functions concerning the IndCpaTest tests.
 *
 * The AES-CBC-PKCS5 algorithm is currently supported.
 *
 * Copyright Opera Software, written by Joshua Rogers.
 *
 */


/*
 * This function decrypts an indcpa-encrypted string, using a provided
 * state and test vector. This function returns a mapping to the result, or
 * raises an error upon an error (i.e. it does does not catch errors).
 */
mapping indcpa_quick_decrypt(mixed state, mapping test) {
    mapping ret = ([ "msg":"" ]);

    state->set_decrypt_key(test["key"]);
    state->set_iv(test["iv"]);

    string(8bit) msg = state->unpad(test["ct"], Crypto.PAD_PKCS7);
    if(!msg) throw(({ "Badpadding" }));
    ret["msg"] = msg;

    return ret;
}

/*
 * This function encrypts a string, using a provided state
 * and test vector. This function returns a mapping to the result, or
 * raises an error upon an error (i.e. it does does not catch errors).
 */
mapping indcpa_quick_encrypt(mixed state, mapping test) {
    mapping ret = ([ "ct":"" ]);

    state->set_encrypt_key(test["key"]);
    state->set_iv(test["iv"]);

    string(8bit) ct = state->crypt(test["msg"]);
    ct += state->pad(Crypto.PAD_PKCS7);

    ret["ct"] = ct;

    return ret;
}

/*
 * This function compares the results of both the encrypting and 
 * decrypting of the provided MSG/CTs in the vector.
 * From here, it checks whether those tests should result in the successful
 * decryption/encryption or not.
 * The function returns whether the test passed (true) or not.
 */
bool indcpa_test_roundtrip(mapping test, string algorithm) {
    mixed state1 = lookup_init(algorithm)();
    mixed state2 = lookup_init(algorithm)();

	begin_ever(test["tcId"], test["comment"]);

    mapping ret_dec;
    mapping ret_enc;

    array err = catch { ret_enc = indcpa_quick_encrypt(state1, test); };

    if(err && test["result"] != "invalid") {
        log_err(DBG_ERROR, false, "Unexpected error while encrypting tcId %d: %O.", test["tcId"], err);
        return false;
    }

    err = catch { ret_dec = indcpa_quick_decrypt(state2, test); };

    if(err) {
        if(test["result"] == "invalid") {
            if(test["flags"] && test["flags"][0] == "BadPadding" && String.count(lower_case(err[0]), "padding") > 0) {
					DBG("BAD PADDING");
                return true;
            }
        }
        log_err(DBG_ERROR, false, "Unexpected error while decrypting tcId %d: %O.", test["tcId"], err);
        return false;
    }

    if(strlen(test["ct"]) % state1->block_size() != 0) {
        log_err(DBG_ERROR, false, "Test tcId %d ciphertext is not a multiple of the block size.", test["tcId"]);
        return false;
    }

    if(test["result"] == "invalid") {
        if(test["flags"] && test["flags"][0] == "BadPadding") {
            DBG("Skipping test tcId %d since BadPadding is not reasonable to test here.", test["tcId"]);
            return true;
        }
        log_err(DBG_ERROR, false, "Test tcId %d should have failed for some reason or another, but it didn't.", test["tcId"]);
        return false;
    }

    if(ret_enc["ct"] != test["ct"]) {
        log_err(DBG_ERROR, false, "Generated CT is not the same as the provided value in tcId %d: %s/%s.", test["tcId"], String.string2hex(ret_enc["ct"]), String.string2hex(test["ct"]));
        return false;
    }

    if(ret_dec["msg"] != test["msg"]) {
        log_err(DBG_ERROR, false, "Generated MSG is not the same as the provided value in tcId %d: %s/%s.", test["tcId"], String.string2hex(ret_dec["msg"]), String.string2hex(test["msg"]));
        return false;
    }

	DBG("GENERAL PASS");

    return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with indcpa-type tests, and returns the number of failed tests.
 */
int indcpa_tests(mapping testGroup, string algorithm) {
//    string type = testGroup["type"];
    int numTests = sizeof(testGroup["tests"]);

    int fail_count = 0;
    for(int j=0; j<numTests; j++) {
        mapping test = testGroup["tests"][j];

        convert_test_to_string(test);
			test["ivSize"] = testGroup["ivSize"];
			test["tagSize"] = testGroup["tagSize"];

			handle_special_actions(test, algorithm);

        if(!indcpa_test_roundtrip(test, algorithm)) {
            fail_count++;
        }
    }

    return fail_count;
}

