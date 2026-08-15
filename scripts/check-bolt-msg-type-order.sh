#!/bin/bash
#
# This script is called in the CI pipeline. It makes sure that the BOLT message
# type constants in smite/src/bolt.rs are listed in increasing order.
# It also makes sure that other code blocks follow that order.

set -eu
set -o pipefail

FILE=smite/src/bolt.rs

order_message_type() {
    # awk '/start/,/end/ { print }' <file>
    #   Print everything between the lines matching start and end
    # grep x3
    #   Print the BOLT message type number inside MessageType() of every line
    awk '/^impl MessageType {/,/^}/ { print }' $FILE | \
        grep "pub const" | \
        grep -oE '= MessageType\([0-9]+\);$' | \
        grep -oE '[0-9]+'
}

echo "Checking order impl MessageType { ... }"
diff -u <(order_message_type) <(order_message_type | sort -n)
echo "OK"

# We now know the keys are in the correct order. We can now use a
# canonical form of the keys to check if other blocks are in the same order.

to_canonical() {
    tr -d ':_ ' | tr '[:upper:]' '[:lower:]'
}

order_canonical_keys() {
    # print all keys in impl MessageType { ... }
    awk '/^impl MessageType {/,/^}/ { print }' $FILE | \
        grep "pub const" | \
        grep -v "pub const fn" | \
        awk '{ print $3 }' | \
        to_canonical
}

order_pub_enum_message() {
    # awk:  print pub enum Message { ... }
    # grep: only keep lines like "Warning(Warning),"
    # sed:  remove everything after first '('
    awk '/^pub enum Message {/,/^}/ { print }' $FILE | \
        grep -E "[A-Za-z0-9]+\([A-Za-z0-9]+\)" | \
        sed 's/(.*//' | \
        to_canonical
}

impl_message_block() {
    awk '/^impl Message {/,/^}/ { print }' $FILE
}

order_impl_message_msg_type() {
    impl_message_block | \
        awk '/^    pub fn msg_type/,/^    }/ { print }' | \
        grep "Self::" | \
        sed -e 's/Self:://' -e 's/(.*//' | \
        grep -v "Unknown" | \
        to_canonical
}

order_impl_message_encode() {
    impl_message_block | \
        awk '/^    pub fn encode/,/^    }/ { print }' | \
        grep "Self::" | \
        sed -e 's/Self:://' -e 's/(.*//' | \
        grep -v "Unknown" | \
        to_canonical
}

order_impl_message_decode() {
    impl_message_block | \
        awk '/^    pub fn decode/,/^    }/ { print }' | \
        grep "MessageType::" | \
        sed -e 's/MessageType:://' -e 's/ =>.*//' | \
        grep -v "Unknown" | \
        to_canonical
}

tests_block() {
    awk '/^mod tests {/,/^}/' $FILE
}

order_tests() {
    tests_block | \
        grep -oE "fn message_[A-Za-z0-9_]+_roundtrip" | \
        grep -v "message_unknown_roundtrip" | \
        sed -e 's/fn message_//' -e 's/_roundtrip//' | \
        to_canonical
}

order_tests_message_type_values() {
    tests_block | \
        awk '/^    fn message_type_values\(\) {/,/^    }/ { print }' | \
        grep -oE "MessageType::[A-Za-z0-9_]+" | \
        sed 's/MessageType:://' | \
        to_canonical
}

echo "Checking pub enum Message { ... }"
diff -u <(order_pub_enum_message) <(order_canonical_keys)
echo "OK"

echo "Checking impl Message::msg_type { ... }"
diff -u <(order_impl_message_msg_type) <(order_canonical_keys)
echo "OK"

echo "Checking impl Message::encode { ... }"
diff -u <(order_impl_message_encode) <(order_canonical_keys)
echo "OK"

echo "Checking impl Message::decode { ... }"
diff -u <(order_impl_message_decode) <(order_canonical_keys)
echo "OK"

echo "Checking roundtrip tests"
diff -u <(order_tests) <(order_canonical_keys)
echo "OK"

echo "Checking message_type_values in tests"
diff -u <(order_tests_message_type_values) <(order_canonical_keys)
echo "OK"
