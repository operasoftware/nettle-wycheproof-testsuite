#include "tables.pike"
function lookup_init(string algorithm) {
	return algo_functions[algorithm];
}

function lookup_function(string schema) {
	return test_function_list[schema];
}

void unset_digest_size(mapping test) {
	test["tagSize"] = "null";
}

void handle_special_actions(mapping test, string algorithm) {
	foreach (special_action_table; string index; function value) {
		if(index == algorithm) {
			value(test);
		}
	}
}


#define ERR_CONT(TYPE,CARR,FMT,ARGS ...) log_err(TYPE,CARR,FMT,ARGS); continue;
#define DBG(FMT,ARGS ...) if(dbg_mode) log_err(DBG_DBG, false, "[L:"+__LINE__+"]"+FMT, ARGS);

#define begin_ever(TCID, COMMENT) if(dbg_mode) log_err(DBG_INFO, true, "Testing tcId [%d] (%s).", TCID, COMMENT); else log_err(DBG_INFO, true, "Testing tcId [%d].", TCID);

//hack to use \r in a round-about way
bool j_car = false;

bool dbg_mode = false;

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

/*
 * Converts various hex-encoded text into their rexpective 8-bit strings.
 */
void convert_test_to_string(mapping test) {
	array convertable = ({"key", "iv", "aad", "msg", "ct", "tag"});

	for(int i=0; i<sizeof(convertable); i++) {
		if(test[convertable[i]])
			test[convertable[i]] = String.hex2string(test[convertable[i]]);
	}
}

/*
 * Returns whether the test should pass or not.
 * TODO: read the error and deal with "Acceptable cases"?.
 */
bool check_pass(array err, string result) {
	switch(result) {
		case "valid":
			return true;
		case "acceptable":
		case "invalid":
			return false;
	}
}
