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
(deftest ^:challenge-12 challenge-9
  (testing "Implement PKCS#7 padding"
    (is (= (let
             [byte-message (.getBytes challenge-9-message)]
             (add-pkcs7-padding byte-message
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

(deftest challenge-11
  (testing "An ECB/CBC detection oracle"
    (is (= (let [plain-text  (map byte (slurp "test/crypto_pals/repeating-plain-text.txt"))
                 trials      100]
             (loop [correct 0
                    trial   0]
               (if (= trial trials)
                 (/ correct trials)
                 (let [[method cipher-text] (encryption-oracle plain-text)
                       true-positive        (and (= method "CBC")
                                                 (cbc? cipher-text))
                       true-negative        (and (= method "ECB")
                                                 (not (cbc? cipher-text)))]
                   (recur (if (or true-positive true-negative)
                            (inc correct)
                            correct)
                          (inc trial))))))
           1))))

(def challenge-11-unknown-string (str "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBt"
                                      "eSByYWctdG9wIGRvd24gc28gbXkgaGFp"
                                      "ciBjYW4gYmxvdwpUaGUgZ2lybGllcyBv"
                                      "biBzdGFuZGJ5IHdhdmluZyBqdXN0IHRv"
                                      "IHNheSBoaQpEaWQgeW91IHN0b3A/IE5v"
                                      "LCBJIGp1c3QgZHJvdmUgYnkK"))
(deftest challenge-12-block-size
  (testing "Block size detection."
    (is (=(let [cipher-key (random-bytes 16)
                plain-text (base64-string-to-bytes challenge-11-unknown-string)
                get-cipher-length (comp count (partial aes-ecb-oracle cipher-key plain-text))
                unpadded-length (get-cipher-length "")
                get-prefix (comp #(map byte %) #(repeat % \A))]
            (loop [n 0]
              (let [length (get-cipher-length (get-prefix n))
                    diff (- length unpadded-length)]
                (if (< 0 diff)
                  diff
                  (recur (inc n))))))
        16))))

(deftest challenge-12-method
  (testing "Block cipher mode detection."
    (is (let [cipher-key (random-bytes 16)
              plain-text (base64-string-to-bytes challenge-11-unknown-string)
              oracle (partial aes-ecb-oracle cipher-key plain-text)
              prefix (map byte (repeat 32 \A))]
          (not (cbc? (oracle prefix)))))))

(deftest ^:challenge-12 ecb-decryption-simple
  (testing "Decrypt an unknown string encrypted in ECB mode."
    (is (= (let [plain-text (base64-string-to-bytes challenge-11-unknown-string)
                 key (random-bytes 16)
                 oracle (partial aes-ecb-oracle key plain-text)]
              (break-ecb oracle))
           (base64-string-to-bytes challenge-11-unknown-string)))))

(deftest ^:challenge-13 key-value-decoding
  (testing "Decode a list of key-value pairs that use the symbols = and &."
    (is (= (kv-decode "foo=bar&baz=qux&zap=zazzle")
           {"foo" "bar", "baz" "qux", "zap" "zazzle"}))))

(deftest ^:challenge-13 key-value-encoding
  (testing "Encode a map as key-value pairs that use the symbols = and &."
    (is (= (kv-encode {"foo" "bar", "baz" "qux", "zap" "zazzle"})
           "foo=bar&baz=qux&zap=zazzle"))))

(deftest ^:challenge-13 profile-generation
  (testing "Create a profile for a given email and return the kv-pair string."
    (is (= (profile-for "foo@bar.com")
           "email=foo@bar.com&uid=10&role=user"))))

(deftest ^:challenge-13 profile-generation-bad-chars
  (testing "Create a profile for a given email and return the kv-pair string. Remove & and = characters."
    (is (= (profile-for "foo@bar.com&role=admin")
           "email=foo@bar.comroleadmin&uid=10&role=user"))))

(deftest ^:challenge-13 ecb-cut-and-paste
  (testing "Create a profile with role=admin using the profile-for function as an oracle."
    (is (= (let [key (random-bytes 16)
                 cipher-text (set-admin-profile (partial profile-oracle key))
                 plain-text (apply str (map char (decryption-oracle key cipher-text)))]
             (get (kv-decode plain-text)
                  "role"))
           "admin"))))

(deftest ^:challenge-14 ecb-prefix-length
  (testing "Derive the size of a random prefix to an ecb oracle."
    (is (let [plain-text (base64-string-to-bytes challenge-11-unknown-string)
                 prefix (random-bytes (rand-int 32))
                 key (random-bytes 16)
                 oracle #(prefixed-ecb-oracle key prefix % plain-text)]
             (= (get-prefix-length oracle)
                (count prefix))))))

(deftest ^:challenge-14 ecb-decryption-hard
  (testing "Decrypt an unknown string encrypted in ECB mode that has a random static prefix."
    (is (= (let [plain-text (base64-string-to-bytes challenge-11-unknown-string)
                 prefix (random-bytes (rand-int 32))
                 _ (println "prefix length=" (count prefix))
                 key (random-bytes 16)
                 oracle #(prefixed-ecb-oracle key prefix % plain-text)
                 result (break-prefixed-ecb oracle)
                 _ (println "--- Challenge 14 result ---")
                 _ (println (apply str (map char result)))]
             result)
           (base64-string-to-bytes challenge-11-unknown-string)))))

(deftest ^:challenge-15 good-padding
  (testing "Validate good PKCS-7 padding."
    (is (= (let [s "ICE ICE BABY"
                 padding '(0x4 0x4 0x4 0x4)
                 message (concat (map byte s) padding)]
              (valid-padding? message))
           true))))

(deftest ^:challenge-15 remove-good-padding
  (testing "Validate and remove good PKCS-7 padding."
    (is (= (let [s "ICE ICE BABY"
                 padding '(0x4 0x4 0x4 0x4)
;                 message (map byte "ICE ICE BABY\u0404\u0404")]
                 message (concat (map byte s) padding)]
             (apply str (map char (remove-padding message))))
           "ICE ICE BABY"))))

(deftest ^:challenge-15 bad-padding
  (testing "Invalidate incorrectly implemented PKCS-7 padding."
    (is (= (let [s "ICE ICE BABY"
                  padding '(1 2 3 4)
                  message (concat (map byte s) padding)]
              (valid-padding? s))
           false))))

(deftest ^:challenge-15 too-short-padding
  (testing "Invalidate PKCS-7 padding that is too short."
    (is (= (let [s "ICE ICE BABY"
                 padding '(5 5 5 5)
                 message (concat (map byte s) padding)]
             (valid-padding? s))
           false))))

(deftest ^:challenge-16 cbc-bit-flipping
  (testing "CBC bit flipping attack."
    (let [key (random-bytes 16)
          iv (random-bytes 16)
          payload (concat (repeat 16 \A) (repeat 16 \B))
          cipher-text (comment-oracle-encrypt iv key payload)
          cipher-text (partition 16 cipher-text)
          payload (map bit-xor (map byte "BBBBB;admin=true")
                       (map bit-xor (nth cipher-text 2)
                            (map byte (repeat 16 \B))))
          cipher-text (flatten (concat (take 2 cipher-text)
                                       payload
                                       (drop 3 cipher-text)))
          plain-text (comment-oracle-decrypt iv key cipher-text)]
      (is (re-find #"admin=true" plain-text)))))

; Sometimes this fails with an error caused by a failure to find any matches
; for a byte. This seems to be a rare occurrence. The padding check is perhaps
; overly strict and prone to both false positives and negatives when an adjacent
; byte happens to be the padding byte. This possibility is mentioned in the
; challenge. There is an element of probability to this technique.
(deftest ^:challenge-17 cbc-padding-oracle-attack
  (testing "Attack a CBC mode padding oracle."
    (let [_ (println "Challenge 17")
          key (random-bytes 16)
          iv (random-bytes 16)
;          cipher-text (random-string-oracle iv key)
          cipher-text (repeatedly 16 #(random-string-oracle iv key))
          oracle (partial padding-oracle iv key)
          plain-text (map #(attack-padding-oracle oracle iv %) cipher-text)
;          plain-text (attack-padding-oracle oracle iv cipher-text)
          _ (println plain-text)]
      (is (= nil "todo")))))

(deftest ^:challenge-18 ctr-decryption
  (testing "Implementation of CTR mode."
    (let [_ (println "Challenge 18")
          key (map byte "YELLOW SUBMARINE")
          nonce (repeat 8 0)
          s "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
          cipher-text (base64-string-to-bytes s)
          plain-text (aes-ctr key nonce cipher-text)
          plain-text (apply str (map char plain-text))
          _ (println plain-text)]
      (is (= plain-text
             "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")))))

(deftest ^:challenge-19 ctr-fixed-nonce-attack
  (testing "Decrypt a series of cipher texts that have reused a nonce."
    (let [nonce (repeat 8 0)
          key (random-bytes 16)
          s '("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=="
               "Q29taW5nIHdpdGggdml2aWQgZmFjZXM="
               "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ=="
               "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4="
               "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk"
               "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
               "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ="
               "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
               "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU="
               "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl"
               "VG8gcGxlYXNlIGEgY29tcGFuaW9u"
               "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA=="
               "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk="
               "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg=="
               "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo="
               "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
               "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA=="
               "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA=="
               "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA=="
               "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg=="
               "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw=="
               "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA=="
               "U2hlIHJvZGUgdG8gaGFycmllcnM/"
               "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w="
               "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4="
               "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ="
               "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs="
               "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA=="
               "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA=="
               "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4="
               "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA=="
               "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu"
               "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc="
               "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs"
               "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs="
               "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0"
               "SW4gdGhlIGNhc3VhbCBjb21lZHk7"
               "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw="
               "VHJhbnNmb3JtZWQgdXR0ZXJseTo="
               "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")
          encrypt (partial aes-ctr key nonce)
          cipher-texts (map (comp encrypt base64-string-to-bytes) s)]
          (is (= (attack-fixed-nonce-ctr cipher-texts)
                 "todo")))))

; todo: map base64 onto results then do a set comparison
(deftest ^:challenge-20 ctr-fixed-nonce-attack-2
  (testing "Decrypt a series of cipher texts that have reused a nonce. I don't understand the difference between this and 19"
    (with-open [r (clojure.java.io/reader "test/crypto_pals/20.txt")]
      (let [nonce (repeat 8 0)
            key (random-bytes 16)
            encrypt (partial aes-ctr key nonce)
            lines (line-seq r)
            cipher-texts (map (comp encrypt base64-string-to-bytes) lines)]
        (is (= (attack-fixed-nonce-ctr cipher-texts)
               "todo"))))))

; "I'm rated \"R\"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed"
; "Cuz I came back to attack others in spite- / Strike like lightnin', It's quite frightenin'!"
; "But don't be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a spark;"
; "Ya tremble like a alcoholic, muscles tighten up / What's that, lighten up! You see a sight but"
; "Suddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quick!"
; "Music's the clue, when I come your warned / Apocalypse Now, when I'm done, ya gone!"
; "Haven't you ever heard of a MC-murderer? / This is the death penalty,and I'm servin' a"
; "Death wish, so come on, step to this / Hysterical idea for a lyrical professionist!"
; "Friday the thirteenth, walking down Elm Street / You come in my realm ya get beat!"
; "This is off limits, so your visions are blurry / All ya see is the meters at a volume"
; "Terror in the styles, never error-files / Indeed I'm known-your exiled!"
; "For those that oppose to be level or next to this / I ain't a devil and this ain't the Exorcist!"
; "Worse than a nightmare, you don't have to sleep a wink / The pain's a migraine every time ya think"
; "Flashbacks interfere, ya start to hear: / The R-A-K-I-M in your ear;"
; "Then the beat is hysterical / That makes Eric go get a ax and chops the wack"
; "Soon the lyrical format is superior / Faces of death remain"
; "MC's decaying, cuz they never stayed / The scene of a crime every night at the show"
; "The fiend of a rhyme on the mic that you know / It's only one capable, breaks-the unbreakable"
; "Melodies-unmakable, pattern-unescapable / A horn if want the style I posses"
; "I bless the child, the earth, the gods and bomb the rest / For those that envy a MC it can be"
; "Hazardous to your health so be friendly / A matter of life and death, just like a etch-a-sketch"
; "Shake 'till your clear, make it disappear, make the next / After the ceremony, let the rhyme rest in peace"
; "If not, my soul'll release! / The scene is recreated, reincarnated, updated, I'm glad you made it"
; "Cuz your about to see a disastrous sight / A performance never again performed on a mic:"
; "Lyrics of fury! A fearified freestyle! / The \"R\" is in the house-too much tension!"
; "Make sure the system's loud when I mention / Phrases that's fearsome"
; "You want to hear some sounds that not only pounds but please your eardrums; / I sit back and observe the whole scenery"
; "Then nonchalantly tell you what it mean to me / Strictly business I'm quickly in this mood"
; "And I don't care if the whole crowd's a witness! / I'm a tear you apart but I'm a spare you a heart"
; "Program into the speed of the rhyme, prepare to start / Rhythm's out of the radius, insane as the craziest"
; "Musical madness MC ever made, see it's / Now an emergency, open-heart surgery"
; "Open your mind, you will find every word'll be / Furier than ever, I remain the furture"
; "Battle's tempting...whatever suits ya! / For words the sentence, there's no resemblance"
; "You think you're ruffer, then suffer the consequences! / I'm never dying-terrifying results"
; "I wake ya with hundreds of thousands of volts / Mic-to-mouth resuscitation, rhythm with radiation"
; "Novocain ease the pain it might save him / If not, Eric B.'s the judge, the crowd's the jury"
; "Yo Rakim, what's up? / Yo, I'm doing the knowledge, E., man I'm trying to get paid in full"
; "Well, check this out, since Norby Walters is our agency, right? / True"
; "Kara Lewis is our agent, word up / Zakia and 4th and Broadway is our record company, indeed"
; "Okay, so who we rollin' with then? We rollin' with Rush / Of Rushtown Management"
; "Check this out, since we talking over / This def beat right here that I put together"
; "I wanna hear some of them def rhymes, you know what I'm sayin'? / And together, we can get paid in full"
; "Thinkin' of a master plan / 'Cuz ain't nuthin' but sweat inside my hand"
; "So I dig into my pocket, all my money is spent / So I dig deeper but still comin' up with lint"
; "So I start my mission, leave my residence / Thinkin' how could I get some dead presidents"
; "I need money, I used to be a stick-up kid / So I think of all the devious things I did"
; "I used to roll up, this is a hold up, ain't nuthin' funny / Stop smiling, be still, don't nuthin' move but the money"
; "But now I learned to earn 'cuz I'm righteous / I feel great, so maybe I might just"
; "Search for a nine to five, if I strive / Then maybe I'll stay alive"
; "So I walk up the street whistlin' this / Feelin' out of place 'cuz, man, do I miss"
; "A pen and a paper, a stereo, a tape of / Me and Eric B, and a nice big plate of"
; "Fish, which is my favorite dish / But without no money it's still a wish"
; "'Cuz I don't like to dream about gettin' paid / So I dig into the books of the rhymes that I made"
; "So now to test to see if I got pull / Hit the studio, 'cuz I'm paid in full"
; "Rakim, check this out, yo / You go to your girl house and I'll go to mine"
; "'Cause my girl is definitely mad / 'Cause it took us too long to do this album"
; "Yo, I hear what you're saying / So let's just pump the music up"
; "And count our money / Yo, well check this out, yo Eli"
; "Turn down the bass down / And let the beat just keep on rockin'"
; "And we outta here / Yo, what happened to peace? / Peace"

(deftest ^:challenge-21 mt19937-implementation-zero-seed
  (testing "Personal implementation of Mersenne Twister 19937 with a zero seed."
    (let []
      (is (= (take 8 (mt19937 0))
             [2357136044
              2546248239
              3071714933
              3626093760
              2588848963
              3684848379
              2340255427
              3638918503])))))

(deftest ^:challenge-21 mt19937-implementation-nonzero-seed
  (testing "Personal implementation of Mersenne Twister 19937 with a non-zero seed."
    (let []
      (is (= (take 8 (mt19937 0xabad1dea))
             [1893883372
              1267561620
              233634371
              786079957
              1296461189
              749209128
              1235140554
              2616046267])))))

; todo: Generate more than n (624) random numbers

(deftest ^:challenge-22 brute-force-mt19937-time-seed
  (testing "Brute force the seed of an MT19937 PRNG that was set as the current time."
    (let [rand-sleep (fn [] (Thread/sleep (* 1000 (+ 40 (rand-int 960)))))
          _ (println "Starting test at" (quot (System/currentTimeMillis) 1000))
          _ (rand-sleep)
          seed (quot (System/currentTimeMillis) 1000)
          r (mt19937 seed)
          _ (rand-sleep)
          _ (println "Starting to guess at" (quot (System/currentTimeMillis) 1000))
          guess (brute-mt19937-time-seed (first r))
          _ (println "Guess:" guess)]
      (is (= guess seed)))))

(deftest ^:challenge-23 clone-mt19937
  (testing "Clone the internal state of an MT19937 PRNG by observing its output."
    (let []
      (is (= 0 1)))
    ))
