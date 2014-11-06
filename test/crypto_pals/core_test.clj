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
