(ns crypto-pals.core-test
  (:require [clojure.test :refer :all]
            [crypto-pals.core :refer :all]
            [clojure.data.codec.base64 :as b64 :refer :all]))

(def set-1-challenge-1-input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
(def set-1-challenge-1-output "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
(deftest set-1-challenge-1
  (testing "Bad conversion of hex to base64."
    (is (= (bytes-to-base64 (hex-to-bytes set-1-challenge-1-input)) set-1-challenge-1-output))))

(def set-1-challenge-2-input-1 "1c0111001f010100061a024b53535009181c")
(def set-1-challenge-2-input-2 "686974207468652062756c6c277320657965")
(def set-1-challenge-2-output "746865206b696420646f6e277420706c6179")

(deftest set-1-challenge-2
  (testing "XOR of two hex string inputs."
    (is (= (apply str
                  (map (comp #(format "%x" %) bit-xor)
                            (hex-to-bytes set-1-challenge-2-input-1)
                            (hex-to-bytes set-1-challenge-2-input-2)))
           set-1-challenge-2-output))))

(deftest frequency
  (testing "Probabilities should accumulate to nearly 1"
    (is (< (Math/abs (- 1.0 (reduce + (map second (seq (english-expected-frequencies))))))
           0.0001))))

(def set-1-challenge-3-input "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
(def set-1-challenge-3-output "Cooking MC's like a pound of bacon")

(deftest set-1-challenge-3
  (testing "Single-byte XOR cipher"
    (is (= (last (first (frequency-test (hex-to-bytes set-1-challenge-3-input)
                                        (english-expected-frequencies))))
           set-1-challenge-3-output))))

(def set-1-challenge-4-input "test/crypto_pals/set-1-challenge-4.txt")
(def set-1-challenge-4-output "Now that the party is jumping\n")

(deftest set-1-challenge-4
  (testing "Detect single-character XOR"
    (is (= (with-open [r (clojure.java.io/reader set-1-challenge-4-input)]
             (let [ranked (sort-by first
                                   (apply concat
                                          (for [line (line-seq r)]
                                            (frequency-test (hex-to-bytes line)
                                                            (english-expected-frequencies)))))]
               (last (first ranked))))
           set-1-challenge-4-output))))

(def set-1-challenge-5-message
  (str "Burning 'em, if you ain't quick and nimble\n"
       "I go crazy when I hear a cymbal"))
(def set-1-challenge-5-key "ICE")
(def set-1-challenge-5-output
  (str "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
       "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))
(deftest set-1-challenge-5
  (testing "Implement repeating-key XOR"
    (is (= (repeating-key-xor (map (comp byte int) set-1-challenge-5-message)
                              (map (comp byte int) set-1-challenge-5-key))
           set-1-challenge-5-output))))

(deftest hamming-test
  (testing "Hamming distance of two strings"
    (is (=(hamming-distance (.getBytes "this is a test")
                            (.getBytes "wokka wokka!!!"))
          37))))

(deftest hamming-test-signed
  (testing "Hamming distance when bytes appear to be signed"
    (is (= (hamming-distance (byte-array (map byte [-112 -104]))
                             (byte-array (map byte [84 -26])))
           9))))

(def set-1-challenge-6-message "test/crypto_pals/set-1-challenge-6.txt")
(def set-1-challenge-6-key-size 29)
(deftest set-1-challenge-6-break-key-size
  (testing "Break repeating-key XOR key size"
    (is (= (let
             [clean-message (apply str (remove #(= \newline %)
                                               (slurp set-1-challenge-6-message)))
              message-bytes (b64/decode (.getBytes clean-message))
              ranked-sizes (rank-key-sizes message-bytes
                                           (range 2 41))]
              (first (first ranked-sizes)))
        set-1-challenge-6-key-size))))

(def set-1-challenge-6-key "Terminator X: Bring the noise")
(deftest set-1-challenge-6-break-key
  (testing "Break repeating-key XOR key"
    (is (= (let
             [clean-message (apply str (remove #(= \newline %)
                                               (slurp set-1-challenge-6-message)))
              message-bytes (b64/decode (.getBytes clean-message))
              key-bytes (break-key message-bytes
                                   set-1-challenge-6-key-size)]
              (apply str (map (comp char #(bit-and 0xff %))
                              key-bytes)))
           set-1-challenge-6-key))))

(def set-1-challenge-6-decrypted-message "test/crypto_pals/set-1-challenge-6-decoded.txt")
(deftest set-1-challenge-6-decode
  (testing "Decoding broken repeating-key XOR"
    (is (=(let
            [clean-message (apply str (remove #(= \newline %)
                                               (slurp set-1-challenge-6-message)))
             message-bytes (b64/decode (.getBytes clean-message))
             message-blocks (partition set-1-challenge-6-key-size
                                       set-1-challenge-6-key-size
                                       []
                                       message-bytes)
             byte-key (map (comp byte int) set-1-challenge-6-key)
             decrypted-message-bytes (mapcat #(map bit-xor byte-key %)
                                             message-blocks)
             decrypted-message (apply str (map (comp char #(bit-and 0xff %))
                                               decrypted-message-bytes))]
            decrypted-message)
          (slurp set-1-challenge-6-decrypted-message)))))

(deftest challenge-7
  (testing "AES in ECB mode"
    (is (= (let
              [cipher-text (base64-file-to-bytes "test/crypto_pals/challenge-7.txt")
               cipher-key (map byte "YELLOW SUBMARINE")
               plain-text (decrypt cipher-key cipher-text)]
             (bytes-to-string plain-text))
           (slurp "test/crypto_pals/challenge-7-decoded.txt")))))

(def set-1-challenge-8-messages "test/crypto_pals/set-1-challenge-8.txt")
(def set-1-challenge-8-ecb-message (str "d880619740a8a19b7840a8a31c810a3d"
                                        "08649af70dc06f4fd5d2d69c744cd283"
                                        "e2dd052f6b641dbf9d11b0348542bb57"
                                        "08649af70dc06f4fd5d2d69c744cd283"
                                        "9475c9dfdbc1d46597949d9c7e82bf5a"
                                        "08649af70dc06f4fd5d2d69c744cd283"
                                        "97a93eab8d6aecd566489154789a6b03"
                                        "08649af70dc06f4fd5d2d69c744cd283"
                                        "d403180c98c8f6db1f2a3f9c4040deb0"
                                        "ab51b29933f2c123c58386b06fba186a"))
(deftest set-1-challenge-8-simple
  (testing "Detect AES in ECB mode"
    (is (= (let
             [ranking (sort-by first
                               (with-open [r (clojure.java.io/reader set-1-challenge-8-messages)]
                                 (doall (for [message (line-seq r)]
                                          (let
                                            [message-bytes (b64/decode (.getBytes message))
                                             message-blocks (partition 16 message-bytes)
                                             distinct-blocks (count
                                                              (frequencies message-blocks))]
                                            (vector distinct-blocks
                                                    (count message-blocks)
                                                    message-bytes))))))
              ecb-message (apply str (map char
                                          (b64/encode (last (first ranking)))))
              _ (println (format "%d of %d blocks are distinct in %s"
                                 (first (first ranking))
                                 (second (first ranking))
                                 ecb-message))]
             ecb-message)
           set-1-challenge-8-ecb-message))))

(def challenge-9-message "YELLOW SUBMARINE")
(def challenge-9-block-size 20)
(def challenge-9-padded-message '(89 69 76 76 79 87 32 83 85 66 77 65 82 73 78 69 4 4 4 4))
(deftest challenge-9
  (testing "Implement PKCS#7 padding"
    (is (= (let
             [byte-message (.getBytes challenge-9-message)]
             (pad-pkcs7 byte-message
                        challenge-9-block-size))
           challenge-9-padded-message))))

(deftest challenge-10
  (testing "Implement CBC mode"
    (is (= (let
             [cipher-key (map byte "YELLOW SUBMARINE")
              iv (map byte (repeat (count cipher-key) 0))
              cipher-text (base64-file-to-bytes "test/crypto_pals/challenge-10.txt")
              blocked-text (decrypt cipher-key cipher-text)
              plain-text (cbc-deblock cipher-text blocked-text iv)]
             (bytes-to-string plain-text))
           (slurp "test/crypto_pals/challenge-10-plain.txt")))))
