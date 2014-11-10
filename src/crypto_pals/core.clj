(ns crypto-pals.core
  (:require [clojure.data.codec.base64 :as b64]
            [clojure.math.numeric-tower :as math]))

(defn base64-string-to-bytes [s]
  (let [convert (comp seq b64/decode byte-array (partial map byte))]
    (convert s)))

(defn base64-file-to-bytes [path]
  (let
    [clean (partial remove #(= \newline %))
     convert (comp seq b64/decode byte-array (partial map byte))]
    (convert (clean (slurp path)))))

(defn write-to-file
  [path content]
  (with-open [w (clojure.java.io/writer path)]
    (.write w content)))

; need to work on numbers not bytes
(defn hex-to-bytes
  [hex]
  (map #(+ (bit-shift-left (first %) 4) (second %))
       (partition 2
                  (map #(Integer/parseInt (String/valueOf %) 16) hex))))
;call these prints, and print
(defn bytes-to-hex
  [bytes]
    (apply str (map #(format "%02x" %) bytes)))

(defn bytes-to-base64
  [bytes]
  (apply str(map char (b64/encode (byte-array bytes)))))

(defn bytes-to-string
  [bytes]
  (apply str (map (comp char #(bit-and 0xff %)) bytes)))

(defn square-difference
  [x y]
  (reduce + (map second (merge-with #(math/expt (- %1 %2) 2) x y))))

(defn transpose [m] (apply mapv vector m))

(defn filter-whitespace
  [string]
  (apply str (filter #(not (clojure.string/blank? (str %))) string)))

(defn count-bits [n]
  (loop [c 0
         ;hack to make negatively signed bytes positive numbers
         v (bit-and n 0xff)]
    (if (zero? v)
      c
      (recur (inc c) (bit-and v (dec v))))))

(defn hamming-distance
  [x y]
  (reduce + (map (comp count-bits bit-xor)
                 x y)))

(defn random-bytes [n]
  (let [rng          (java.security.SecureRandom.)
        random-bytes (byte-array n)]
    (.nextBytes rng random-bytes)
    (seq random-bytes)))

;https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
(defn english-expected-frequencies
  []
  (let
    [regular {\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253
              \e 0.12702 \f 0.02228 \g 0.02015 \h 0.06094
              \i 0.06966 \j 0.00153 \k 0.00772 \l 0.04025
              \m 0.02406 \n 0.06749 \o 0.07507 \p 0.01929
              \q 0.00095 \r 0.05987 \s 0.06327 \t 0.09056
              \u 0.02758 \v 0.00978 \w 0.02360 \x 0.00150
              \y 0.01974 \z 0.00074}
     special {\* 0.0 \space 0.0 \. 0.0 \, 0.0}]
    (merge regular special)))

(defn build-frequency-table
  [string expected]
  (let [alpha (filter (set (map first expected))
                      (clojure.string/lower-case (clojure.string/replace string #"[^a-zA-Z .,]" "*")))]
    (into {} (for [[k v ] (frequencies alpha)]
               [k (/ v (count alpha))]))))

(defn frequency-test
  [in expected]
  (let [ranked (sort-by first
                        (for [c (range 0 256)]
                          (let [s (apply str (map (comp char #(bit-and 0xff %) #(bit-xor c %)) in))
                                score (square-difference (build-frequency-table s expected)
                                                         expected)]
                            (list score c s))))]
    ranked))

(defn repeating-key-xor
  [message key]
  (let
     [key-length (count key)
      message-subs (partition key-length key-length [] message)]
    (bytes-to-hex (mapcat #(map bit-xor % key) message-subs))))

(defn rank-key-sizes [message sizes]
  (sort-by second
           (for [size sizes]
             (let
               [block-pairs (partition 2 1 (partition size message))]
               (list size
                     (/ (reduce + (map #(/ (hamming-distance (first %)
                                                             (second %))
                                           size)
                                       block-pairs))
                        (count block-pairs)))))))

(defn break-key
  [message size]
  (let
    [transposed-message (transpose (partition size message))]
    (for [row transposed-message]
        (second (first (frequency-test row (english-expected-frequencies)))))))

(defn cbc? [cipher-text]
  (let [blocks          (partition 16 cipher-text)
        count-distinct  (comp count frequencies)
        duplicates      (- (count blocks) (count-distinct blocks))]
  (= 0 duplicates)))

(defn pad-pkcs7
  [message block-size]
  (let
    [padding (repeat block-size
                     0x04)]
    (flatten
     (partition block-size
                block-size
                padding
                message))))

(defn encrypt [cipher-key plain-text]
  (let [key-spec (javax.crypto.spec.SecretKeySpec. (byte-array cipher-key) "AES")
        cipher   (javax.crypto.Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key-spec)
    (seq (.doFinal cipher (byte-array plain-text)))))

(defn decrypt
  [cipher-key cipher-text]
  (let
    [key-spec (javax.crypto.spec.SecretKeySpec. (byte-array cipher-key) "AES")
    cipher (javax.crypto.Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher javax.crypto.Cipher/DECRYPT_MODE key-spec)
    (seq (.doFinal cipher (byte-array cipher-text)))))

(defn cbc-block [iv cipher plain-text]
  (let [encrypt-block (comp list cipher #(map bit-xor %1 %2))
        encrypt-all   (comp flatten #(drop 1 %) (partial reduce #(concat %1
                                                                         (encrypt-block (last %1) %2))))]
    (encrypt-all (list iv)
                 (partition (count iv) plain-text))))

(defn cbc-deblock [cipher-text plain-text iv]
  (let [block-size  (count iv)
        cipher-text (concat (list iv)
                            (partition block-size cipher-text))
        plain-text  (partition block-size plain-text)
        deblock     (comp flatten (partial map #(map bit-xor %1 %2)))]
    (deblock plain-text cipher-text)))

(defn encryption-oracle [plain-text]
  (let [block-size 16
        cipher-key (random-bytes block-size)
        rand-zero-pad (comp #(map byte %) #(repeat % 0))
        rand-5-10 #(+ 5 (rand-int 6))
        padded-message (pad-pkcs7 (concat (rand-zero-pad (rand-5-10))
                                          plain-text
                                          (rand-zero-pad (rand-5-10)))
                                  block-size)]
    (if (= 0 (rand-int 2))
      ;use ECB
      (vector "ECB" (encrypt cipher-key padded-message))
      ;use CBC
      (let
        [iv (random-bytes block-size)
         cipher (partial cbc-block iv (partial encrypt cipher-key))]
        (vector "CBC" (cipher padded-message))))))
