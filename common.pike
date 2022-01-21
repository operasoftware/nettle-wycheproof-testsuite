/*
 * common.pike: Common Functions.
 *
 * Various functions which are used throughout different Pike files of
 * this project, such as for error logging.
 */

#include "tables.pike"

#define ERR_CONT(TYPE,CARR,FMT,ARGS ...) log_err(TYPE,CARR,FMT,ARGS); continue;
#define DBG(FMT,ARGS ...) if(dbg_mode) log_err(DBG_DBG, false, "[L:"+__LINE__+"]"+FMT, ARGS);
#define begin_ever(TCID, COMMENT) if(dbg_mode) log_err(DBG_INFO, true, "Testing tcId [%d] (%s).", TCID, COMMENT); else log_err(DBG_INFO, true, "Testing tcId [%d].", TCID);

bool j_car = false; //horrible hack to use carriages for logging
bool dbg_mode = false;
string force_test;

/*
 * Returns the correct function to initalize a state (normally)
 */
function lookup_init(string algorithm) {
	return algo_functions[algorithm];
}

/*
 * Returns the correct function to test for an algorithm/schema.
 */
function lookup_function(string schema) {
	return test_function_list[schema];
}

/*
 * Handles each 'special action' for specific algorithms
 */
void handle_special_actions(mapping test, string algorithm) {
	foreach (special_action_table; string index; function value) {
		if(index == algorithm) {
			value(test);
		}
	}
}

/*
 * Converts various hex-encoded text into their rexpective 8-bit strings.
 */
void convert_test_to_string(mapping test) {
	array convertable = ({"key", "iv", "aad", "msg", "ct", "sig", "tag", "public"});

	for(int i=0; i<sizeof(convertable); i++) {
		if(test[convertable[i]])
			test[convertable[i]] = String.hex2string(test[convertable[i]]);
	}
}

/*
 * Returns the hash function for different SHA algorithms
 */

mixed get_sha_function(string sha_string) {
	mixed sha;
	switch(sha_string) {
		case "SHA-1":
			sha = Crypto.SHA1;
			break;
		case "SHA-224":
			sha = Crypto.SHA224;
			break;
		case "SHA-256":
			sha = Crypto.SHA256;
			break;
		case "SHA-384":
			sha = Crypto.SHA384;
			break;
		case "SHA-512":
			sha = Crypto.SHA512;
			break;
		case "SHA3-224":
			sha = Crypto.SHA3_224;
			break;
		case "SHA3-256":
			sha = Crypto.SHA3_256;
			break;
		case "SHA3-384":
			sha = Crypto.SHA3_384;
			break;
		case "SHA3-512":
			sha = Crypto.SHA3_512;
			break;
#if constant(Crypto.SHA512_256)
		case "SHA-512/256":
			sha = Crypto.SHA512_256;
			break;
#endif
#if constant(Crypto.SHA512_224)
		case "SHA-512/224":
			sha = Crypto.SHA512_224;
			break;
#endif
		default:
//			log_err(DBG_ERROR, false, "Unknown SHA function (%s)!", sha_string); // should be handled by the caller
			break;
	}

	return sha;
}

/*
 * Main logging function. Either ends the message with a carriage or
 * a newline, depending on whether the script is run in dbg mode, 
 * and/or the 'carriage' variable is true.
 */
void log_err(int type, bool carriage, string fmt, mixed ... args) {
	if(!carriage && j_car)
		write("\n");

	if(type != DBG_DBG || (type == DBG_DBG && dbg_mode))
		write(colors[type]+fmt, @args);

	write("\x1B[0m");

	if(carriage) {
		if(!dbg_mode) {
			write("\r");
			j_car = true;
		} else {
			write("\n");
		}
	} else {
		write("\n");
		j_car = false;
	}
}
