(ns crypto-pals.core
  (:require [clojure.data.codec.base64 :as b64]
            [clojure.math.numeric-tower :as math]))

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

(defn print-as-string
  [bytes]
  (println (apply str (map char bytes))))

(defn square-difference
  [x y]
  (reduce + (map second (merge-with #(math/expt (- %1 %2) 2) x y))))

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
