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
 * rsa_verify.pike: Functions concerning the RsassaPkcs1Verify tests.
 */

/*
 * The main test for RsassaPkcs1Verify tests.
 * This function simply sets the public key, then verifies the message
 * and signature.
 * The function returns whether the test was successful(true) or not.
 */
bool rsa_verify_test(mapping test, string algorithm) {
	begin_ever(test["tcId"], test["comment"]);

	mixed state = lookup_init(algorithm)(test["keyAsn"]);
	mixed sha = get_sha_function(test["sha"]);

	if(!sha) {
		DBG("Skipping tcId %d because Pike does not support the SHA function %s.", test["tcId"], test["sha"]);
		return true;
	}

	bool ret;
	array err = catch { ret = state->pkcs_verify(test["msg"], sha, test["sig"]); };

	if(err && err[0] == "Unknown ASN.1 id for hash.\n") {
		DBG("SHA function not supported");
		return true;
	} else if(err) {
		log_err(DBG_ERROR, false, "Error while verifying tcId %d: (%O).", test["tcId"], err);
		return false;
	}

	if(test["result"] == "invalid") {
		if(ret) {
			log_err(DBG_ERROR, false, "Successful verify on an invalid testcase tcId %d.", test["tcId"]);
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
 * This function deals with RsassaPkcs1Verify tests, and returns the number of failed tests.
 */
int rsa_verify_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	string keyAsn = String.hex2string(testGroup["publicKeyAsn"]);
	string sha = testGroup["sha"];

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		handle_special_actions(test, algorithm);

		test["keyAsn"] = keyAsn;
		test["sha"] = sha;

		if(!rsa_verify_test(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
