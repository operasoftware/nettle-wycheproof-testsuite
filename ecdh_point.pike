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
 * ecdh_point.pike: Functions concerning the EcdhEcpointTest tests.
 * It's not completely clear what tests should be conducted here, so
 * this script simply loads the publickey/point, and checks whether
 * it was successful.
 */


/*
 * The main test for EcdhEcpointTest tests.
 * This function simply sets the public key. No actual tests are performed.
 * The function returns whether the test was successful(true) or not.
 */
bool ecdh_point_test(mapping test, string algorithm) {
	mixed curve = lookup_init(algorithm);

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

	mixed ret;

	array err = catch { ret = curve->Point(Stdio.Buffer(test["public"])); };

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
 * This function deals with EcdhEcpointTest tests, and returns the number of
 * failed tests.
 */
int ecdh_point_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	string curve = testGroup["curve"];

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];
		convert_test_to_string(test);

		handle_special_actions(test, algorithm);

		test["curve"] = curve;

		if(!ecdh_point_test(test, algorithm)) {
			fail_count++;
			continue;
		}
	}

	return fail_count;
}
