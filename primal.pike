/*
 * primal.pike: Functions concerning the PrimalityTest tests.
 */

/*
 * The main test for PrimalityTest tests.
 * This function simply creates a Gmp object, and determines whether
 * the number is "probably" in a prime number, using Donald Knuth's
 * primality test.
 * The function returns whether the test was successful(true) or not.
 */
bool test_primality(mapping test) {
	begin_ever(test["tcId"], test["comment"]);

	Gmp.mpz num = Gmp.mpz(test["value"], 16);
	int prime = num->probably_prime_p();

	if(prime > 0) {
		if(test["result"] == "valid") {
			DBG("PRIME");
			return true;
		}
		if(test["result"] == "acceptable") {
			DBG("ACCEPTABLE PRIME");
			return true;
		}
		log_err(DBG_ERROR, false, "probably_prime_p() says tcId is a prime, but it isn't.", test["tcId"]);
		return false;
	}

	if(test["result"] != "valid") {
		DBG("NOT A PRIME");
		return true;
	}

	log_err(DBG_ERROR, false, "probably_prime_p() says tcId %d is not a prime, but it should be.", test["tcId"]);

	return false;
}

/*
 * This function loops through each of the tests, and runs the cases through
 * each of the function(s) corresponding to the type of test.
 * This function deals with PrimalityTest tests, and returns the number of failed tests.
 */
int prime_tests(mapping testGroup, string algorithm) {
	int numTests = sizeof(testGroup["tests"]);

	int fail_count = 0;
	for(int j=0; j<numTests; j++) {
		mapping test = testGroup["tests"][j];

		handle_special_actions(test, algorithm);
		if(!test_primality(test)) {
			fail_count++;
		}
	}

	return fail_count;
}
