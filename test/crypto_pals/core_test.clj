(ns crypto-pals.core-test
  (:require [clojure.test :refer :all]
            [crypto-pals.core :refer :all]))

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
