#!/bin/sh

# some vars and setup
export LD_LIBRARY_PATH=../lib
# note: cwd will be a subdir of this one
KEYGEN="../../examples/ldns-keygen"
SIGNZONE="../../examples/ldns-signzone"

mkdir -p tmpdata
cd tmpdata

# generate a zone
cat > example.org <<EOF
example.org. 3600 IN SOA invalid. hostmaster.example.org. (10 43200 900 1814400 7200)
example.org. 3600 IN NS invalid.
example.org. 3600 IN A 192.0.2.1
example.org. 3600 IN AAAA 2:2001:db8::1
EOF

test_sign_existingkey() {
    NAME=$1
    KEYFILE="../testdata/$2"
    EXPECTED_OUTPUT="../testdata/$3"
    OUTPUT_FILE="${NAME}_example.org.signed"
    ${SIGNZONE} -i 20000101000000 -e 20300101000000 -f ${OUTPUT_FILE} example.org ${KEYFILE}
    diff ${OUTPUT_FILE} ${EXPECTED_OUTPUT}
    if [ $? -ne 0 ]; then
      echo "Test FAILED: ${NAME} output ${OUTPUT_FILE} not the same as ${EXPECTED_OUTPUT}"
      return
    fi;
    echo "Test success: ${NAME}"
}

test_sign_newkey() {
    ALGORITHM=$1
    KEYSIZE=$2
    KEYFILE=`${KEYGEN} -r /dev/urandom -a ${ALGORITHM} example.org | tail -n 1`
    if [ $? != 0 ]; then
        echo "Error generating key for algorithm ${ALGORITHM}, aborting"
        exit $?
    fi
    echo "KEY FILE: ${KEYFILE}"
    ${SIGNZONE} -i 20000101000000 -e 20300101000000 example.org ${KEYFILE}

}

# generate keys
#test_sign_newkey RSASHA3_256 1024
test_sign_existingkey rsasha3_256 sha3_256_key ref_rsasha3_256_example.org.signed
