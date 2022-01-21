/*
 * main.pike: The main program file.
 *
 * Nettle is a cryptographic library created by the Linkoping University,
 * and comes pre-packaged in the Pike scripting language.
 *
 * The Wycheproof project provides tests for cryptographic algorithms,
 * which professionals have published in an attempt to secure different
 * libraries.
 *
 * This program attempts to cycle through each of the tests with
 * the algorithms available in Pike/Nettle, and detect any errors
 * based on the tests.
 *
 * Created by Joshua Rogers for Opera Software.
 */

#include "common.pike"
#include "aead.pike"
#include "indcpa.pike"
#include "dsa.pike"
#include "ecdsa.pike"
#include "eddsa.pike"
#include "ecdh_point.pike"
#include "mactest.pike"
#include "primal.pike"
#include "rsa_verify.pike"
#include "rsa_generate.pike"
#include "rsa_decrypt.pike"

/*
 * Prepares an array of mappings from JSON files
 */
array prepare_json_cases() {
	mapping(string:mapping(string:string)) json_vector;
	array(mapping(string:mapping(string:string))) maps = allocate(sizeof(test_vectors));
	int cases = 0;
	int totaltests = 0;

	for (int i=0; i<sizeof (test_vectors); i++) {
		object file = Stdio.File();
		if(!file->open("testvectors/"+test_vectors[i],"r")) {
			ERR_CONT(DBG_ERROR,false,"Missing file: %s. Skipping.",test_vectors[i]);
		}

		string json_data = file->read();
		file->close();
		array err = catch {
			json_vector = Standards.JSON.decode(json_data);
		};

		if(err) {
			ERR_CONT(DBG_ERROR,false,"Invalid JSON loaded from %s: %s. Skipping.", test_vectors[i], describe_error(err)-"\n");
		}

		if(!lookup_init((string)json_vector["algorithm"])) {
			ERR_CONT(DBG_INFO, false, "Loaded JSON from %s, but skipping due to the lack of support in Pike/Nettle of the algorithm %s.", test_vectors[i], (string)json_vector["algorithm"]);
		}

		if(force_test && force_test != (string)json_vector["algorithm"]) {
			ERR_CONT(DBG_INFO, false, "Loaded JSON from %s, but skipping due to force-ful mode.", test_vectors[i]);
		}

		maps[cases] = json_vector;
		maps[cases++]["file"] = (["name": test_vectors[i]]);
		totaltests += (int)json_vector["numberOfTests"];
		ERR_CONT(DBG_INFO,false,"Loaded JSON from %s.", test_vectors[i]);
	}

	log_err(DBG_INFO, false,"%d test vectors loaded, totalling %d tests.", cases, totaltests);

	return maps;
}

/*
 * Driver/Main script.
 */
int main(int argc, array(string) argv) {
	for(int j=1; j<argc; j++) {
		if(argv[j] == "D")
			dbg_mode = true;
		else
			force_test = argv[j];
	}
	array maps = prepare_json_cases();

	if(maps[0] == 0) {
		log_err(DBG_ERROR, false, "No test vectors to check. Exiting.");
		return 1;
	}

	for(int i=0; i<sizeof(maps) && maps[i]; i++) {
		string algorithm = maps[i]["algorithm"];
		int fail_count = 0;

		log_err(DBG_INFO, false, "Beginning tests for %s(%s).", algorithm, maps[i]["file"]["name"]);

		for(int j=0; j<sizeof(maps[i]["testGroups"]); j++) {
			mixed testGroup = maps[i]["testGroups"][j];
			function function_to_use = lookup_function(maps[i]["schema"]);

			if(function_to_use)
				fail_count += function_to_use(testGroup, algorithm);
		}

		log_err((fail_count == 0) ? DBG_SUCCESS : DBG_ERROR, false, "Finished testing %s. %d/%d failed tests.", algorithm, fail_count, maps[i]["numberOfTests"]);
	}
}
