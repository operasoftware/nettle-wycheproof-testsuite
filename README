# Pike-Wycheproof

Pike-Wycheproof is a project to utilize the [Wycheproof](https://github.com/google/wycheproof) cryptographic testcases in Pike, in order to test both the Nettle cryptographic library, and Pike's glue(bindings) to the library.

Various vectors of tests are grouped together into common testing types, each corresponding to a file in the project. Because each testing type generally follow the same formula (e.g. `encrypt()`; `decrypt()`; `verify()`), each vector shares similar functions. In specific cases of common testing types needing irregular actions to be taken, the `special_action_table` array (in `tables.pike`) handles one(or more)-off functions which can be used to prepare the special cases. For example, the AeadTest-type algorithm "AES-GCM" is special from other AeadTest-types, in that it cannot calculate a truncated digest, and thus special handling must be done to the test's data before the testing begins.

The program is made in such a way that new testcases can be added more-or-less in a plug-and-play fashion.
For example, if new [IndCpaTest](https://github.com/google/wycheproof/blob/master/doc/files.md#IndCpaTest) (corresponding to the [ind_cpa_test_schema.json](https://github.com/google/wycheproof/blob/master/doc/types.md#indcpatestgroup) test group) test vectors are released in the future, it is only necessary to update the file `tables.pike` with an addition to the array `test_vectors` of the new vector's filename (and possible to the mapping `algo_functions` if a different algorithm is used).

## Usage

```shell
# Runs all of the Wycheproof tests in Pike.
pike main.pike

# Runs the tests with verbose debugging information
pike main.pike D
```

## Results
A list of issues found by this program are listed below.

### Crypto.AES.CCM
1. Null Pointer Dereference
[Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10072)
2. Incorrect Digest [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10074)

### Crypto.DSA
1. Infinite loop [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10075)
## License
The Wycheproof project and its testcases are provided under the apache-2.0 license.
