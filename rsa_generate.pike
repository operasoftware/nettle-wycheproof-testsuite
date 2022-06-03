/*
 * Copyright (C) 2022 Opera Norway AS. All rights reserved.
 * This file is an original work developed by Joshua Rogers.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

     http:www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
 * rsa_generate.pike: Functions concerning the RsassaPkcs1Generate tests.
 */

/*
 * The main test for RsassaPkcs1Generate tests.
 * This function simply sets the private key, then generates a digest
 * from the provided message.
 * The function returns whether the test was successful(true) or not.
 */
bool rsa_generate_test(mapping test, string algorithm) {
	begin_ever(test["tcId"], test["comment"]);

	mixed state = lookup_init(algorithm)(test["privateKeyPkcs8"]);
	mixed sha = get_sha_function(test["sha"]);

	if(!sha || test["sha"] == "SHA-224") {
		DBG("Skipping tcId %d because Pike does not support the SHA function %s.", test["tcId"], test["sha"]);
		return true;
	}

	string ret;
	array err = catch { ret = state->pkcs_sign(test["msg"], sha); };

	if(err && test["result"] == "valid") {
		log_err(DBG_ERROR, false, "Error while generating tcId %d: (%O).", test["tcId"], err);
		return false;
	}

	if(test["sig"] == ret) {
		if(test["result"] == "invalid") {
			log_err(DBG_ERROR, false, "Signature match on seemingly invalid case tcId %d.", test["tcId"]);
			return false;
		}
	} else {
		if(test["result"] == "valid") {
			log_err(DBG_ERROR, false, "Signature mismatch on seemingly valid case tcId %d.", test["tcId"]);
			return false;
		}
	}

	DBG("GENERAL PASS");
	return true;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with RsassaPkcs1Generate tests, and returns the number of failed tests.
 */
int rsa_generate_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	string privateKeyPkcs8 = String.hex2string(testGroup["privateKeyPkcs8"]);
	string sha = testGroup["sha"];

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		handle_special_actions(test, algorithm);

		test["privateKeyPkcs8"] = privateKeyPkcs8;
		test["sha"] = sha;

		if(!rsa_generate_test(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
