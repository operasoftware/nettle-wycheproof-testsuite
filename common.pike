/*
 * common.pike: Common Functions.
 *
 * Various functions which are used throughout different pike files of
 * this project, such as for error logging.
 */

#include "tables.pike"

#define ERR_CONT(TYPE,CARR,FMT,ARGS ...) log_err(TYPE,CARR,FMT,ARGS); continue;
#define DBG(FMT,ARGS ...) if(dbg_mode) log_err(DBG_DBG, false, "[L:"+__LINE__+"]"+FMT, ARGS);
#define begin_ever(TCID, COMMENT) if(dbg_mode) log_err(DBG_INFO, true, "Testing tcId [%d] (%s).", TCID, COMMENT); else log_err(DBG_INFO, true, "Testing tcId [%d].", TCID);

bool j_car = false; //horrible hack to use carriages for logging
bool dbg_mode = false;

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
	array convertable = ({"key", "iv", "aad", "msg", "ct", "sig", "tag"});

	for(int i=0; i<sizeof(convertable); i++) {
		if(test[convertable[i]])
			test[convertable[i]] = String.hex2string(test[convertable[i]]);
	}
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
